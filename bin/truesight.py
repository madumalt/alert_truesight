import sys, os
import json
import logging
import logging.handlers


def setup_logger(level):
    logger = logging.getLogger('alert_truesight')
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)

    file_handler = logging.handlers.RotatingFileHandler(
        '/Users/thilinamad/Desktop/splunk_enterprise/splunk' + '/var/log/splunk/alert_truesight.log', 
        maxBytes=25000000, 
        backupCount=5
    )
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger
 
logger = setup_logger(logging.DEBUG)

def alert_truesight(settings, hostname, ip_address, object_class_name, object_name, parameter, severity):
    logger.debug(settings)
    logger.info(f'hostname: {hostname}, ip: {ip_address}, object_class: {object_class_name}, object: {object_name},' 
        + f'parameter: {parameter}, severity: {severity}')
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("FATAL Unsupported execution mode (expected --execute flag)\n")
        sys.exit(1)
    try:
        settings = json.loads(sys.stdin.read())
        config = settings['configuration']
        success = alert_truesight(
            settings,
            hostname=config.get('hostname'),
            ip_address=config.get('ip'),
            object_class_name=config.get('object_class'),
            object_name=config.get('object'),
            parameter=config.get('parameter'),
            severity=config.get('severity')
        )
        if not success:
            sys.exit(2)
    except Exception as e:
        sys.stderr.write("ERROR Unexpected error: %s\n" % e)
        sys.exit(3)
