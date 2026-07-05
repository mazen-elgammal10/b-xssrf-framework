import logging
import sys
import os


def silence_all():
    # 🔥 منع أي logging (stdlib)
    logging.disable(logging.CRITICAL)

    # 🔥 امسح handlers القديمة
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # 🔥 اقفل androguard بالكامل (الجزء اللي بيستخدم stdlib logging)
    for name in list(logging.root.manager.loggerDict.keys()):
        if name.startswith("androguard"):
            logger = logging.getLogger(name)
            logger.handlers = []
            logger.propagate = False
            logger.setLevel(logging.CRITICAL)

    # 🔥 androguard بيستخدم loguru كمان (خصوصًا في ARSC/resource dimension parsing)
    # وده نظام منفصل تمامًا عن logging.disable() فوق، فلازم نقفله لوحده
    try:
        from loguru import logger as loguru_logger
        loguru_logger.remove()
    except ImportError:
        pass
    except ValueError:
        # لو الـ sinks اتشالت قبل كده، remove() من غير args ممكن ترمي ValueError
        pass

    # 🔥 اقفل stdout مؤقتاً (للـ tools المزعجة)
    sys.stdout.flush()
    sys.stderr.flush()
