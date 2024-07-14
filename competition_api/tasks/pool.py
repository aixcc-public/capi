import arq
from arq.connections import ArqRedis, RedisSettings
from vyper import v


def get_queue_name(worker_id: str) -> str:
    return f"arq:queue:{worker_id}"


async def fastapi_get_task_pool() -> ArqRedis:
    return await arq.create_pool(RedisSettings(**v.get("redis.kwargs")))
