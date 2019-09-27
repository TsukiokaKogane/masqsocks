import asyncio
import logging
import urllib
from aiohttp import web
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime


class BadProtocolVersion(Exception):    # 错误协议版本异常
    pass


class BadRequest(Exception):     # 错误请求异常
    pass


def generate_json_response(state, address, port):   # 动态生成http的json回应（注意json的内容格式与封装）
    reply = b'HTTP/1.1 200 OK\r\nDate: '
    now = datetime.now()
    stamp = mktime(now.timetuple())
    reply += format_date_time(stamp).encode()
    reply += b'\r\nContent-Type: application/json;\r\nContent-Length: '
    # print(state)
    # print(address)
    # print(port)
    content = web.json_response({'state': state, 'addr': address, 'port': port})
    reply += str(content.content_length).encode()
    reply += b'\r\n\r\n'
    reply += content.body
    # print(reply)
    return reply


def generate_response(data):    # 动态生成http的字节流内容回应（注意字节流的内容格式与封装）
    reply = b'HTTP/1.1 200 OK\r\nDate: '
    now = datetime.now()
    stamp = mktime(now.timetuple())
    reply += format_date_time(stamp).encode()
    reply += b'\r\nContent-Type: application/octet-stream;\r\nContent-Length: '
    length = len(data)
    reply += str(length).encode()
    reply += b'\r\n\r\n'
    reply += data
    # print('reply=')
    # print(reply)
    return reply


def request_handler(data):  # 解析SOCKS5连接请求的内容信息
    dataset = data.split(b'\r\n')
    header = dataset[0].split(b' ')
    method, url, protocol = header
    if method != b'GET':
        raise BadRequest
    if protocol != b'HTTP/1.1' and protocol != b'HTTP/1.1':
        raise BadProtocolVersion
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    return query[b'address_type'], query[b'address'], query[b'port'], query[b'local_host'], query[b'local_port']


async def get_content(header, reader):  # 通过伪装的http头获取数据
    header = header.split(b'\r\n\r\n')[0]
    length = header.split(b'Content-Length: ')[1]
    length = int(length.decode())
    data = await reader.read(length)
    return data


async def recv_data(reader, writer):    # 数据转发：从AS获得数据，伪装后发送给ML
    timeout_counter = 3     # 超时计数器
    while True:
        # await asyncio.sleep(0.1)
        data = await reader.read(65536)     # 从AS获得数据
        # print('recv=')
        # print(data)
        if data is b'' or data is None:     # 数据为空
            if timeout_counter == 0:    # 超时临界
                break
            else:
                timeout_counter = timeout_counter - 1   # 超时
        else:
            timeout_counter = 3     # 超时复位

        # print(data)
        writer.write(generate_response(data))    # 伪装后发送给ML
        await writer.drain()


async def send_data(reader, writer):       # 数据转发：从ML获得数据，去伪装后发送给AS
    timeout_counter = 3     # 超时计数器
    while True:
        data = await reader.readuntil(b'\r\n\r\n')     # 从ML获得伪装后数据头部
        # print('send=')
        # print(data)
        data = await get_content(data, reader)  # 从伪装后数据头部获得数据内容
        if data is b'' or data is None:     # 数据为空
            if timeout_counter == 0:     # 超时临界
                break
            else:
                timeout_counter = timeout_counter - 1   # 超时
        else:
            timeout_counter = 3     # 超时复位
        # print('data=')
        # print(data)
        writer.write(data)      #发送给AS
        await writer.drain()


async def mr_handler(reader, writer):    # 接受MR连接请求
        logging.info('Receive connection from %s', writer.get_extra_info('peername'))
        data = await reader.readuntil(b'\r\n\r\n')   # 获得伪装后SOCKS5连接请求的头部
        #print(data)
    # try:
        address_type, address, port, local_host, local_port = request_handler(data)     # 获得解析连接请求后的信息
        address_type = address_type[0].decode()
        address = address[0].decode()
        port = int(port[0].decode())
        local_host = local_host[0].decode()
        local_port = int(local_port[0].decode())
        logging.info('target url is %s %s', address, port)  # 显示解析连接请求后的信息
        # print(local_host)
        # print(local_port)
        # remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # remote.connect((address, port))
        # bind_address = remote.getsockname()
        remote_reader, remote_writer = await asyncio.open_connection(address, port)     # 连接AS
        addr = remote_writer.get_extra_info('peername')
        address = addr[0]
        port = addr[1]
        logging.info('Connected to %s %s' % (address, port))    # 显示AS连接信息
        state = 'success'
        # print(address)
        # print(port)
        writer.write(generate_json_response(state, address, port))  # 发送ML伪装后的AS连接信息
        await writer.drain()
        # ml_reader, ml_writer = await asyncio.open_connection(local_host, local_port)
        # print(ml_writer.get_extra_info('peername'))
        logging.info('Start data redirection')  # 开始数据转发
        task1 = asyncio.create_task(send_data(reader, remote_writer))   # 异步接受（ML）发送(AS)协程
        task2 = asyncio.create_task(recv_data(remote_reader, writer))    # 异步接受(AS) 发送（ML）协程
        await task1
        await task2


async def main():
    server = await asyncio.start_server(mr_handler, '127.0.0.1', 9011)      # 在9011端口开启本地服务器
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')     # 显示本地服务器信息
    async with server:
        await server.serve_forever()        # 异步永久执行本地服务器

logging.getLogger().setLevel(logging.INFO)  # 设置debug信息过滤级别
asyncio.run(main())     # 异步执行主函数
