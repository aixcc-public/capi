import arq
from arq.connections import ArqRedis, RedisSettings
from vyper import v

v.set_default("redis.host", "127.0.0.1")
v.set_default("redis.port", 6379)


def build_redis_settings() -> RedisSettings:
    return RedisSettings(
        host=v.get("redis.host"),
        port=v.get("redis.port"),
        password=v.get("redis.password"),
    )


async def fastapi_get_task_pool() -> ArqRedis:
    return await arq.create_pool(build_redis_settings())
