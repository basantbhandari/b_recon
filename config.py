import yaml

with open("config.yml", "r") as yamlfile:
    data = yaml.load(yamlfile, Loader=yaml.FullLoader)


class Config:
    DOMAIN_NAME = data.get('domain_name')
    OUTPUT_DIR = data.get('output_dir')
    SUBDOMAIN_ENUMERATION_WORLD_LIST = data.get('subdomain_enumeration_worldlist')
    SUB_JECK_FINGUREPRINT = data.get('sub_ject_fingureprint')
