import asyncio
import struct
import logging
import socket
import json
from IPy import IP

SOCKS_VERSION = 5  # SOCKS_VERSION版本
MR_url = "http://127.0.0.1:9011/"   # MR的url
MR_host = '127.0.0.1'# MR的Host
MR_port = 9011 # MR的端口
# local_addr = ()

usrname = 'admin'   # 默认SOCKS02认证方式用户名
passwd = '123456'   # 默认SOCKS02认证方式密码


class BadSocksVersion(Exception):   # 错误SOCKS版本异常
    pass


class BadAddressType(Exception):    # 错误地址格式异常
    pass


class UnsupportedYet(Exception):    # 错误请求方式异常
    pass


class MRConnectionError(Exception):     # MR连接异常
    pass


class AuthenticationFailure(Exception):      # SOCKS02认证方式认证失败
    pass


async def get_available_methods(reader, n):    # 获取可用的SOCKS请求方式
    methods = []
    method_set = await reader.read(n)
    for i in range(n):
        methods.append(method_set[i])
    return methods


def generate_http_post_request(data):   # 动态生成http的post请求
    request = b'POST / HTTP/1.1\r\n'
    request += b'Host: '
    request += MR_host.encode()
    request += b':'
    request += str(MR_port).encode()
    request += b'\r\n'
    request += b'Content-Type: application/application/octet-stream;\r\nContent-Length: '
    request += str(len(data)).encode()
    request += b'\r\n\r\n'
    request += data
    return request


async def get_content(header, reader):  # 通过伪装的http头获取数据
    header = header.split(b'\r\n\r\n')[0]
    length = header.split(b'Content-Length: ')[1]
    length = int(length.decode())
    data = await reader.read(length)
    return data


async def recv_data(reader, writer):    # 数据转发：从MR获得数据，去伪装后发送给AC
    timeout_counter = 3     # 超时计数器
    while True:
        # await asyncio.sleep(0.1)
        data = await reader.readuntil(b'\r\n\r\n')  # 获得伪装http头部
        # print('recv=')
        # print(data)
        data = await get_content(data, reader)  # 通过伪装的http头获取数据
        # print('data=')
        # print(data)
        if data is b'' or data is None:  # 数据为空
            if timeout_counter == 0:
                break   # 超时临界
            else:
                timeout_counter = timeout_counter - 1   # 超时
        else:
            timeout_counter = 3     # 超时复位


        # print(data)
        # print(get_http_content(data))
        writer.write(data)  # 发送给AC
        await writer.drain()


async def send_data(reader, writer):    # 数据转发：从AC获得数据，伪装后发送给MR
    timeout_counter = 3  # 超时计数器
    while True:
        # await asyncio.sleep(0.1)
        data = await reader.read(65536)     # 从AC获得数据
        if data is b'' or data is None:     # 数据为空
            if timeout_counter == 0:
                break   # 超时临界
            else:
                timeout_counter = timeout_counter - 1   # 超时
        else:
            timeout_counter = 3  # 超时复位
        # print('send=')
        # print(data)
        data = generate_http_post_request(data)     # 生成伪装数据

        writer.write(data)  # 发送给MR
        await writer.drain()


def generate_http_get_request(address_type, address, port):     # 动态生成http的get请求
    request = b'GET /?'
    request += b'address_type='
    request += str(address_type).encode()
    request += b'&'
    request += b'address='
    request += address.encode()
    request += b'&'
    request += b'port='
    request += str(port).encode()

    request += b'&'
    request += b'local_host='
    request += b'127.0.0.1'

    request += b'&'
    request += b'local_port='
    request += str(8888).encode()

    request += b' HTTP/1.1\r\n'
    request += b'Host: '
    request += MR_host.encode()
    request += b':'
    request += str(MR_port).encode()
    request += b'Accept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Python/3.7 aiohttp/3.5.4\r\n\r\n'
    return request


async def verify_credentials(reader, writer):   # SOCKS 02方式认证
    version = ord(await reader.read(1))
    assert version == 1
    username_len = ord(await reader.read(1))
    username = reader.read(username_len).decode('utf-8')
    password_len = ord(reader.read(1))
    password = reader.read(password_len).decode('utf-8')
    global usrname
    global passwd
    if username == usrname and password == passwd:
        # 验证成功, status = 0
        response = struct.pack("!BB", version, 0)
        writer.write(response)
        return True
    # 验证失败, status != 0
    response = struct.pack("!BB", version, 0xFF)
    writer.write(response)
    await writer.drain()
    writer.close()
    return False


async def ml_handler(reader, writer):   # 接受ML连接请求
    try:
        # 1 request
        header = await reader.read(2)   # 读取SOCKS请求头部
        logging.info("Received new ML request from %s", writer.get_extra_info('peername'))
        version, nmethods = struct.unpack("!BB", header)
        if version != SOCKS_VERSION:    # 读取SOCKS请求头部
            raise BadSocksVersion
        assert nmethods > 0     # 接受的表示方法数不为零
        methods = await get_available_methods(reader, nmethods)
        if 0 not in methods:     # 接受的表示方法00不可用
            if 2 not in methods:    # 接受的表示方法02也不可用
                raise UnsupportedYet    # 不支持异常
            else:
                if verify_credentials(reader, writer) is False:  # 接受的表示方法02认证失败
                    raise AuthenticationFailure
        else:    # 接受的表示方法00
            # 2 response
            writer.write(struct.pack("!BB", SOCKS_VERSION, 0))
            await writer.drain()
        # 3 request
        info = await reader.read(4)
        version, cmd, _, address_type = struct.unpack("!BBBB", info)
        assert version == SOCKS_VERSION
        if address_type == 1:  # IPv4
            address = socket.inet_pton(socket.AF_INET, await reader.read(4))
        elif address_type == 3:  # Domain name
            domain_length = ord(await reader.read(1))
            address = await reader.read(domain_length)
        elif address_type == 3:  # IPv6
            address = socket.inet_pton(socket.AF_INET6, await reader.read(6))
        port = struct.unpack('!H', await reader.read(2))[0]
        mr_reader, mr_writer = await asyncio.open_connection(MR_host, MR_port)  # 连接MR
        # print(mr_writer.get_extra_info('peername'))
        print(generate_http_get_request(address_type, address.decode(), port))
        mr_writer.write(generate_http_get_request(address_type, address.decode(), port))    # 发送MR伪装后的连接信息
        recv = await mr_reader.readuntil(b'\r\n\r\n')   # 读取MR伪装后的连接信息回应头部
        recv = await get_content(recv, mr_reader)   # 获得 MR伪装后的连接信息回应内容
        data = json.loads(recv)  # 读取 MR伪装后的连接信息回应json内容
            # print(data)
        if data['state'] == 'failed':   # 连接失败 发送AC失败SOCKS回应包 退出
            if IP(address).version() == 4:
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, 1, struct.unpack("!I", socket.inet_aton(address))[0], data['port'])
            elif IP(address).version() == 6:
                reply = struct.pack("!BBBBQQH", SOCKS_VERSION, 5, 0, 4,
                                        struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, address))[0],
                                        struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, address))[1],
                                        data['port'])
            writer.write(reply)
            await writer.drain()
            raise ConnectionError
        else:   # 连接成功 发送AC成功SOCKS回应包 进入数据转发
            if IP(data['addr']).version() == 4:
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                                    struct.unpack("!I", socket.inet_pton(socket.AF_INET,data['addr']))[0], data['port'])
            elif IP(data['addr']).version() == 6:
                reply = struct.pack("!BBBBQQH", SOCKS_VERSION, 0, 0, 4,
                                        struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, data['addr']))[0],
                                        struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, data['addr']))[1],
                                        data['port'])
        writer.write(reply)
        await writer.drain()
        if cmd != 1:  # BIND OR UDP ASSOCIATE
            logging.info("connection closed")
            writer.close()
            return
        logging.info('Start data redirection')  # 开始数据转发
        task1 = asyncio.create_task(send_data(reader, mr_writer))   # 异步接受（AC）发送(MR)协程
        task2 = asyncio.create_task(recv_data(mr_reader, writer))   # 异步接受(MR) 发送（AC）协程
        await task1
        await task2
    except BadSocksVersion:
        logging.critical('unsupported socks version')
    except BadAddressType:
        logging.critical('unsupported address type')
    except UnsupportedYet:
        logging.critical('unsupported function yet')
    except ConnectionError:
        logging.critical('couldn\'t connect to MR')
    except Exception as err:
        logging.error(err)
    await writer.drain()
    logging.info("connection closed")
    writer.close()


async def main():   # 主函数
    server = await asyncio.start_server(ml_handler, '127.0.0.1', 8888)  # 在8888端口开启本地服务器
    addr = server.sockets[0].getsockname()
    # global local_addr
    # local_addr = addr
    print(f'Serving on {addr}')  # 本地服务器信息
    async with server:
        await server.serve_forever()    # 异步永久执行本地服务器
logging.getLogger().setLevel(logging.INFO)  # 设置debug信息过滤级别
asyncio.run(main())     # 异步执行主函数
