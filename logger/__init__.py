from typing import Union
import functools
import logging
from logger.logger import MyLogger
from colorama import Fore


def get_default_logger():
    return MyLogger().get_logger()


def b_logger(_func=None, *, my_logger: Union[MyLogger, logging.Logger] = None):
    def decorator_log(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if my_logger is None:
                logger = get_default_logger()
            else:
                if isinstance(my_logger, MyLogger):
                    logger = my_logger.get_logger(func.__name__)
                else:
                    logger = my_logger
            args_repr = [repr(a) for a in args]
            kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
            signature = ", ".join(args_repr + kwargs_repr)
            logger.debug(f"{Fore.GREEN}function {func.__name__} called with args {signature}")
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                logger.exception(f"{Fore.RED}Exception raised in {func.__name__}. exception: {str(e)}")
                raise e
        return wrapper

    if _func is None:
        return decorator_log
    else:
        return decorator_log(_func)