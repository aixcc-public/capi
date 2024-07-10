import arq
from arq.connections import ArqRedis, RedisSettings
from vyper import v

v.set_default("redis.host", "127.0.0.1")
v.set_default("redis.port", 6379)
v.set_default("redis.ssl", False)


def build_redis_settings() -> RedisSettings:
    return RedisSettings(
        host=v.get("redis.host"),
        port=v.get_int("redis.port"),
        password=v.get("redis.password"),
        ssl=v.get_bool("redis.ssl"),
    )


async def fastapi_get_task_pool() -> ArqRedis:
    return await arq.create_pool(build_redis_settings())
