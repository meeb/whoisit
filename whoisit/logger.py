import os
import sys
import logging


debug_env_var = str(os.getenv('DEBUG', '')).strip().lower()
is_debugging = debug_env_var in ('yes', 'y', '1', 'true')
default_level = logging.DEBUG if is_debugging else logging.INFO


def get_logger(name, level=default_level):
    log = logging.getLogger(name)
    log.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    fmt = logging.Formatter('%(asctime)s %(name)s [%(levelname)s] %(message)s')
    ch.setFormatter(fmt)
    log.addHandler(ch)
    return log
