import arq
from arq.connections import ArqRedis, RedisSettings
from vyper import v


async def fastapi_get_task_pool() -> ArqRedis:
    return await arq.create_pool(RedisSettings(**v.get("redis.kwargs")))
