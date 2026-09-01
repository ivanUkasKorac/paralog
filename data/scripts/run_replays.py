#!/usr/bin/env python3
"""
Pokrece replay.py za svaku .yml datoteku u direktoriju generiranim paralog_generatorom
(jedan .yml po hostnameu, npr. attack_scenario_DC01.yml).

Koristenje:
    python3 run_replays.py <path_to_replay.py> <attack_scenario_dir> [--index INDEXNAME]

"""

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Pokrece replay.py za svaki .yml u direktoriju scenarija napada.")
    parser.add_argument("replay_path", help="Putanja do replay.py")
    parser.add_argument("scenario_dir", help="Direktorij s raspakiranim attack_scenario_*.yml/.log datotekama")
    parser.add_argument("--index", default="test", help="Naziv indexa (default: test)")
    args = parser.parse_args()

    replay_path = Path(args.replay_path).resolve()
    scenario_dir = Path(args.scenario_dir).resolve()

    if not replay_path.is_file():
        print(f"[ERROR] replay.py nije pronaden: {replay_path}")
        sys.exit(1)
    if not scenario_dir.is_dir():
        print(f"[ERROR] scenarij napada nije pronaden: {scenario_dir}")
        sys.exit(1)

    yml_files = sorted(scenario_dir.glob("*.yml"))
    if not yml_files:
        print(f"[ERROR] nema .yml datoteka u {scenario_dir}")
        sys.exit(1)

    print(f"Pronadeno {len(yml_files)} .yml datoteka u {scenario_dir}")
    print()

    success = 0
    for yml_file in yml_files:
        print(f"=== {yml_file.name} ===")
        result = subprocess.run(["python3", str(replay_path), str(yml_file.name), f"--index={args.index}"], cwd=scenario_dir)
        if result.returncode != 0:
            print(f"[ERROR] {yml_file.name} zavrsio s exit kodom {result.returncode}")
            sys.exit(1)
        success += 1
        print()

    print(f"Gotovo: {success} Hostova uspjesno poslano.")

if __name__ == "__main__":
    main()
