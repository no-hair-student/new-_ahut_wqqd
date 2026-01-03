import base64
import hashlib
import json
import logging
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urlparse
import requests


"""
                更新日志
2026年1月3日：
  修改用户类可以直接传入md5加密之后的密码，通过is_encrypted属性选择。
  将generate_sign更新为学校现行版本。
  添加了多个随机UA及访问各接口前添加随机延时，模拟人工操作。
"""


@dataclass
class User:
    # 学号(必须填写)
    student_Id: int
    # 姓名(获取token时可自动获取)
    username: str = ''
    # 密码(若未修改考勤系统密码可以留空)
    password: str = "Ahgydx@920"
    # 纬度(根据所需签到的情况填写，可采用默认值)
    latitude: float = 118.554951
    # 经度(根据所需签到的情况填写，可采用默认值)
    longitude: float = 31.675607
    # 用户专属token(无需填写，实时获取)
    token: str = None
    # 签到任务的内部Id(无需填写，实时获取)
    taskId: int = None
    # 当前提供的密码是否为加密之后的
    is_encrypted: int = 0


## *------------------------------------------------------* ##
##            请在此处完成您的配置 ([]内的为可选列表)            ##
## *------------------------------------------------------* ##

# log输出的等级 (logging.[DEBUG,INFO,WARNING,ERROR,CRITICAL])
#       []内的为可选列表，推荐logging.INFO)
LOG_GRADE = logging.DEBUG
# 用户列表，每一个元素是用户对象，具体内容请参考class User
# 本处所给的是四个样例，实际使用时请根据实际填写
USER_LIST = [
    # 使用参考
    # User(259000000),
    # User(259000001, "诸天神佛"),
    # User(259000003, "保我代码", "new_password"),
    # User(259000004, "不出BUG", latitude=118.227, longitude=31.668),

    # 此处使用随机学号进行调试，实际情况请使用需要签到学生的学号
    User(random.randint(259024000,259025000))
]
# 单次尝试签到最大尝试次数
MAX_RETRIES = 4
# 单次尝试签到因TOKEN失效最大额外尝试次数
MAX_TOKEN_RETRIES = 3
## *------------------------------------------------------* ##





## *------------------------------------------------------* ##
##                         日志设置区                         ##
## *------------------------------------------------------* ##

# 日志格式设定
formatter = logging.Formatter(
    fmt='%(levelname)s [%(name)s] (%(asctime)s): %(message)s (Line: %(lineno)d [%(filename)s])',
    datefmt='%Y/%m/%d %H:%M:%S'
)

# 获取日志记录器，并设定显示等级
logger = logging.getLogger()
logger.setLevel(LOG_GRADE)

# 添加控制台handler以输出日志
console_handler = logging.StreamHandler(stream=sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.DEBUG)
logger.addHandler(console_handler)

# 屏蔽第三方库的logging日志
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("dbutils").setLevel(logging.WARNING)
logging.getLogger("yagmail").setLevel(logging.WARNING)
## *------------------------------------------------------* ##





## *------------------------------------------------------* ##
##                         常量声明区                         ##
## *------------------------------------------------------* ##

# 学校考勤系统api_url
API_BASE_URL = "https://xskq.ahut.edu.cn/api"

# 执行完整签到流程所涉及的url
WEB_DICT = {
    # 获取用户token
    "token_api": f"{API_BASE_URL}/flySource-auth/oauth/token",
    # 获取当前签到taskId
    "task_id_api": f"{API_BASE_URL}/flySource-yxgl/dormSignTask/getStudentTaskPage?userDataType=student&current=1&size=15",
    # 获取微信接口配置，确保考勤系统记录中用户是通过微信尝试签到
    "auth_check_api": f"{API_BASE_URL}/flySource-base/wechat/getWechatMpConfig"
                      "?configUrl=https://xskq.ahut.edu.cn/wise/pages/ssgl/dormsign"
                      "?taskId={TASK_ID}&autoSign=1&scanSign=0&userId={STUDENT_ID}",
    # 开启签到的时间窗口
    "apiLog_api": f"{API_BASE_URL}/flySource-base/apiLog/save?menuTitle=%E6%99%9A%E5%AF%9D%E7%AD%BE%E5%88%B0",
    # 进行晚寝签到
    "sign_in_api": f"{API_BASE_URL}/flySource-yxgl/dormSignRecord/add",
    # 获取未签到列表
    "sign_in_result_api": f"{API_BASE_URL}/flySource-yxgl/dormSignStu/getWqdStudentPage"
                          "?taskId={taskId}&xhOrXm=&nowDate={date_str}&userDataType=student&current=1&size=100",
}

# 可选的UA头列表
UA_LIST = [
    "Mozilla/5.0 (Linux; Android 15; MIX Fold 4 Build/TKQ1.240502.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.137 Mobile Safari/537.36 MicroMessenger/8.0.61.2660(0x28003D37) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
    "Mozilla/5.0 (Linux; Android 15; LYA-AL10 Build/HUAWEILYA-AL10; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.137 Mobile Safari/537.36 MicroMessenger/8.0.61.2660(0x28003D37) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64",
    "Mozilla/5.0 (Linux; Android 15; SM-S938B Build/TP1A.240205.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.137 Mobile Safari/537.36 MicroMessenger/8.0.61.2660(0x28003D37) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.61(0x18003D29) NetType/WIFI Language/zh_CN",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.61(0x18003D29) NetType/5G Language/zh_CN",
]
## *------------------------------------------------------* ##





## *------------------------------------------------------* ##
##                         功能方法区                         ##
## *------------------------------------------------------* ##

def password_md5(pwd: str) -> str:
    """
    使用 MD5 算法对用户密码进行加密。

    :param pwd: 需加密的明文字段
    :return: 加密后的字符串
    """
    return hashlib.md5(pwd.encode('utf-8')).hexdigest()


def generate_sign(url, token) -> str:
    """
    实时生成指定用户访问指定网页的访问令牌。

    :param url: 所需访问的url
    :param token: user所持有的令牌token
    :return: 指定的网页令牌
    """
    if not token:
        return None
    parsed_url = urlparse(url)
    api = parsed_url.path + "?sign="
    timestamp = int(time.time() * 1000)
    inner = f"{timestamp}{token}"
    inner_hash = hashlib.md5(inner.encode("utf-8")).hexdigest()
    raw = f"{api}{inner_hash}"
    final_hash = hashlib.md5(raw.encode("utf-8")).hexdigest()
    encoded_time = base64.b64encode(str(timestamp).encode("utf-8")).decode("utf-8")
    return f"{final_hash}1.{encoded_time}"


def get_time() -> dict:
    """
    获取当前时间，并以结构化格式返回。

    :return: 格式化后的时间
    """
    now = time.localtime()
    date = time.strftime("%Y-%m-%d", now)
    current_time = time.strftime("%H:%M:%S", now)
    full_datetime = time.strftime("%Y年%m月%d日 %H:%M:%S", now)
    week_list = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    weekday = week_list[now.tm_wday]
    return {
        "date": date,
        "time": current_time,
        "weekday": weekday,
        "full": full_datetime
    }


def generate_header(user: User, url: str = None) -> dict:
    """
    为user访问指定url生成对应的请求头，建议一段时间后更新UA

    :param user: User对象
    :param url: 所需访问的url
    :return: 访问所需的header
    """
    header = {
        'User-Agent': random.choice(UA_LIST),
        'authorization': "Basic Zmx5c291cmNlX3dpc2VfYXBwOkRBNzg4YXNkVURqbmFzZF9mbHlzb3VyY2VfZHNkYWREQUlVaXV3cWU=",
        'Content-Type': "application/json;charset=UTF-8",
        'X-Requested-With': "com.tencent.mm",
        'Origin': "https://xskq.ahut.edu.cn",
        'Referer': f"https://xskq.ahut.edu.cn/wise/pages/ssgl/dormsign?&userId={user.student_Id}"
    }
    if user.token:
        header['flysource-auth'] = f"bearer {user.token}"
        if url:
            header['flysource-sign'] = generate_sign(url, user.token)
    return header


def generate_params(user: User):
    """
    为user生成获取token时必须的查询参数

    :param user: User对象
    :return: 所需的查询参数字典
    """
    return {
        'tenantId': '000000',
        'username': user.student_Id,
        'password': user.password if user.is_encrypted else password_md5(user.password),
        'type': 'account',
        'grant_type': 'password',
        'scope': 'all'
    }


def generate_data(user: User) -> dict:
    """
    为user生成对应的data用于签到请求时发送

    :param user: User对象
    :return: 规范后的data字典
    """
    date = get_time()
    return {
        "taskId": user.taskId,
        "signAddress": "",
        "locationAccuracy": round(random.uniform(25, 35), 2),
        "signLat": user.latitude,
        "signLng": user.longitude,
        "signType": 0,
        "fileId": "",
        "imgBase64": "/static/images/dormitory/photo.png",
        "signDate": date["date"],
        "signTime": date["time"],
        "signWeek": date["weekday"],
        "scanCode": "",
    }


## *------------------------------------------------------* ##





## *------------------------------------------------------* ##
##                       主要功能实现区                       ##
## *------------------------------------------------------* ##

def sign_in_by_step(user: User, step: int, debug: bool = False) -> dict:
    """
    为指定user执行step步的签到过程，旨在实现错误重试

    :param user: 执行晚寝签到的User对象
    :param step: 当前需要执行的步骤数
    :param debug: 是否处于debug模式
    :return: {success:当前步骤是否完成, msg:错误信息, step:下一次将要进行的步骤}
    """
    # 签到前时间检验
    if not debug:
        now_time = get_time()['time']
        if now_time < '21:20:00':
            logger.error(f'当前时间 {now_time} 未到签到时间，不进行签到')
            return {'success': False,'msg':"未到签到时间",'step': -1}

    # 获取token
    if step == 0:
        logger.info(f"开始为 {user.student_Id} 获取token")
        token_result = requests.post(WEB_DICT["token_api"], params=generate_params(user),headers=generate_header(user)).json()
        logger.debug(f'{user.student_Id} 获取token返回信息 {token_result}')

        if 'refresh_token' in token_result:
            user.token = token_result['refresh_token']
            user.username = token_result['userName']
            logger.info(f"成功为 {user.username}({user.student_Id}) 获取到token")
            logger.debug(f"{user.username}({user.student_Id}) 的token为 {user.token}")
            return {'success': True, 'msg':'','step':step+1}

        else:
            error_desc = token_result.get('error_description','未知错误')
            if "Bad credentials" in error_desc or "用户名或密码错误" in error_desc: error_desc = "密码错误"
            logger.error(f"为 {user.student_Id} 获取token时，出现错误：{error_desc}")
            return {'success': False, 'msg': error_desc, 'step': -1}


    # 获取taskId
    if step == 1:
        logger.info(f"开始为 {user.username}({user.student_Id}) 获取当前签到taskId")
        task_result = requests.get(WEB_DICT['task_id_api'], headers=generate_header(user,WEB_DICT['task_id_api'])).json()
        logger.debug(f"{user.username}({user.student_Id}) 获取taskId返回信息 {task_result}")

        if task_result['code'] == 200:
            if task_result.get('data', {}).get('records', [{}])[0].get("taskId"):
                user.taskId = task_result.get('data').get('records')[0].get('taskId')
                logger.info(f"为 {user.username}({user.student_Id}) 获取到当前签到的taskId：{user.taskId}")
                return {'success': True, 'msg': '', 'step': step+1}
            else:
                logger.error(f"{user.username}({user.student_Id}) 获取taskId时未在返回信息中解析到taskId字段，请检查{task_result}")
                return {'success': False, 'msg': '未在返回信息中解析到taskId字段', 'step': step}

        else:
            if (("请求未授权" in task_result.get('msg'))
                    or ("缺失身份信息" in task_result.get('msg'))
                    or ('鉴权失败' in task_result.get('msg'))):
                logger.warning(f"{user.username}({user.student_Id}) Token失效或未授权，将重试获取Token。")
                user.token = ''
                return {'success': False, 'msg': 'token失效', 'step': 0}
            else:
                logger.warning(f"{user.username}({user.student_Id}) 获取taskId时出现问题：{task_result.get('msg')}")
                return {'success': False, 'msg': task_result.get('msg'), 'step': step}

    # 获取微信接口配置
    if step == 2:
        logger.info(f"开始为 {user.username}({user.student_Id}) 获取微信接口配置")
        url =WEB_DICT['auth_check_api'].format(TASK_ID=user.taskId,STUDENT_ID=user.student_Id)
        auth_result = requests.get(url, headers=generate_header(user,url)).json()
        logger.debug(f"{user.username}({user.student_Id}) 获取微信接口配置返回信息 {auth_result}")

        if auth_result['code'] == 200:
            logger.info(f"为 {user.username}({user.student_Id}) 获取微信接口配置信息成功")
            return {'success': True, 'msg': '', 'step': step+1}

        else:
            if (("请求未授权" in auth_result.get('msg'))
                    or ("缺失身份信息" in auth_result.get('msg'))
                    or ('鉴权失败' in auth_result.get('msg'))):
                logger.warning(f"{user.username}({user.student_Id}) Token失效或未授权，将重试获取Token。")
                user.token = ''
                return {'success': False, 'msg': 'token失效', 'step': 0}
            else:
                logger.warning(
                    f"{user.username}({user.student_Id}) 获取微信接口配置信息时出现问题：{auth_result.get('msg')}")
                return {'success': False, 'msg': auth_result.get('msg'), 'step': step}

    # 开启时间窗口
    if step == 3:
        logger.info(f"开始为 {user.username}({user.student_Id}) 开启签到时间窗口")
        # apiLog_result = requests.post(WEB_DICT['apiLog_api'], headers=generate_header(user,WEB_DICT['apiLog_api'])).json()
        apiLog_result = requests.post(WEB_DICT['apiLog_api'], headers=generate_header(user, WEB_DICT['apiLog_api']))
        logger.debug(f"{user.username}({user.student_Id}) 开启签到时间窗口返回信息 {apiLog_result.text}")
        # apiLog_result = apiLog_result.json()

        # if apiLog_result['code'] == 200:
        #     logger.info(f"为 {user.username}({user.student_Id}) 开启签到时间窗口成功")
        #     return {'success': True, 'msg': '', 'step': step + 1}

        if apiLog_result.status_code == 200:
            logger.info(f"为 {user.username}({user.student_Id}) 开启签到时间窗口成功")
            return {'success': True, 'msg': '', 'step': step + 1}

        else:
            logger.warning(
                f"{user.username}({user.student_Id}) 开启签到时间窗口时出现问题")
            return {'success': False, 'msg': "开启签到时间窗口时出现问题", 'step': step}

    # 进行晚寝签到
    if step == 4:
        logger.info(f"开始为 {user.username}({user.student_Id}) 晚寝签到")
        sign_in_result = requests.post(WEB_DICT['sign_in_api'], data=json.dumps(generate_data(user)), headers=generate_header(user,WEB_DICT['sign_in_api'])).json()
        logger.debug(f"{user.username}({user.student_Id}) 晚寝签到返回信息 {sign_in_result}")

        if sign_in_result['code'] == 200:
            logger.info(f"为 {user.username}({user.student_Id}) 晚寝签到成功")
            return {'success': True, 'msg': '', 'step': step + 1}

        else:
            if (("请求未授权" in sign_in_result.get('msg'))
                    or ("缺失身份信息" in sign_in_result.get('msg'))
                    or ('鉴权失败' in sign_in_result.get('msg'))):
                logger.warning(f"{user.username}({user.student_Id}) Token失效或未授权，将重试获取Token。")
                user.token = ''
                return {'success': False, 'msg': 'token失效', 'step': 0}
            else:
                if '未到签到时间！' in sign_in_result.get('msg'):
                    logger.warning(
                        f"因当前时间{get_time()['time']}未到签到时间，{user.username}({user.student_Id}) 签到失败")
                    return {'success': False, 'msg': sign_in_result.get('msg'), 'step': -1}
                logger.warning(
                    f"{user.username}({user.student_Id}) 晚寝签到时出现问题：{sign_in_result.get('msg')}")
                return {'success': False, 'msg': sign_in_result.get('msg'), 'step': step}

    # 未知情况或传入的step错误
    else:
        logger.debug(f"出现未知错误，当前参数为：user={user.student_Id},step={step}")
        return {'success': False, 'msg': '', 'step': -1}


def sign_in(user: User, debug: bool = False):
    """
    为单人进行晚寝签到尝试

    :param user: 尝试晚寝签到的User对象
    :param debug: 是否为debug模式，此模式下忽略签到时间限制
    :return: {success:签到结果, data:签到过程中出现的错误}
    """
    logger.info(f"为 {user.username}({user.student_Id}) 尝试执行签到")
    step, retries, token_retries = 0, 0, 0
    error_history = set()

    while retries < MAX_RETRIES and 0 <= step < 5:
        result = sign_in_by_step(user, step, debug)
        step = result['step']
        if not result['success']:
            error_history.add(result['msg'])
            if step == 0 and token_retries < MAX_TOKEN_RETRIES:
                token_retries += 1
            else:
                retries += 1
        # 添加随机延时，模拟手动操作
        time.sleep(random.randint(50,150)/100)

    if step == 5:
        return {'success': True, 'data': error_history}
    else:
        return {'success': False, 'data': error_history}


## *------------------------------------------------------* ##


# 串行执行签到流程
# if __name__ == '__main__':
#     results = {}
#     start_time = time.time()
#     for u in USER_LIST:
#         results[u.student_Id] = sign_in(u) # 如需在非签到时间内测试可传入参数debug=True
#     end_time = time.time()
#     print(f"本次为 {len(USER_LIST)} 人尝试进行签到，成功人数：{sum([1 if result['success'] else 0 for result in results.values()])}，"
#           f"本次任务总耗时 {end_time - start_time:.2f} 秒。\n本次任务详细结果如下：")
#     for k,v in results.items():
#         print(f"\t{k}: {v}")



# 多线程执行签到流程(多线程无法保证日志输出的连贯性，如出现错误，请移步串行执行审查)
if __name__ == '__main__':
    results = {}
    start_time = time.time()

    # 设置最大线程数
    max_workers = min(20,len(USER_LIST))

    # 使用线程池多线程执行
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures_to_user = {
            # 如需在非签到时间内测试可传入参数debug=True
            executor.submit(sign_in, u, debug=True): u for u in USER_LIST
        }
        for future in as_completed(futures_to_user):
            u = futures_to_user[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"success": False, "msg": str(e)}
            results[u.student_Id] = result

    end_time = time.time()
    print(f"本次为 {len(USER_LIST)} 人尝试进行签到，成功人数：{sum([1 if result['success'] else 0 for result in results.values()])}，"
          f"本次任务总耗时 {end_time - start_time:.2f} 秒。\n本次任务详细结果如下：")
    for k,v in results.items():
        print(f"\t{k}: {v}")