from functools import lru_cache
from pathlib import Path

import yaml


RULE_FILE = Path("rules/detection_rules.yml")


@lru_cache(maxsize=1)
def load_detection_rules(rule_file=RULE_FILE):
    if not Path(rule_file).exists():
        return {}

    with open(rule_file, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    rules = data.get("rules", [])

    return {
        rule["rule_id"]: rule
        for rule in rules
        if rule.get("rule_id")
    }


def get_rule(rule_id):
    return load_detection_rules().get(rule_id, {})
