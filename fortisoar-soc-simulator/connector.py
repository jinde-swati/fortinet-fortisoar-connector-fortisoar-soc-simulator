from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, _check_health
from django.utils.module_loading import import_string
from .utils import *
from .constants import LOGGER_NAME 


logger = get_logger(LOGGER_NAME)

class FortiSOARSocSimulator(Connector):

      
    def on_add_config(self, config, active):
        scenarios = next(os.walk(os.path.join(os.path.dirname(__file__),"scenarios")))[1]
        
        if(config.get('load_threat')):
          load_threat()
        
        
        if(config.get('import_records')):
          for scenario in scenarios:
              record_data_file = os.path.join(os.path.dirname(__file__),"scenarios/"+scenario+"/scenario_record.json")
              record_data = json.load(open(record_data_file, "rb"))
              records = record_data.get('records')
              import_records(records,scenario)

    def on_update_config(self, old_config, new_config, active):
        if new_config.get('import_records'):
          for scenario in scenarios:
              record_data_file = os.path.join(os.path.dirname(__file__),"scenarios/"+scenario+"/scenario_record.json")
              record_data = json.load(open(record_data_file, "rb"))
              records = record_data.get('records')
              import_records(records,scenario)
        
        if new_config.get('load_threat'):
          load_threat()

    def execute(self, config, operation, params, *args, **kwargs):
        action = operations.get(operation)
        return action(params)

    def check_health(self, config=None, *args, **kwargs):
        _check_health()