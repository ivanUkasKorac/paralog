#!/usr/bin/env python3
"""
Paralog Generator
Generira zapise razrješavanjem placeholdera u predlošcima napada koristeći podatke iz datoteke mrežne topologije.

Placeholder grammar:
    {{TIMESTAMP:FORMAT}}                    FORMAT moze biti SYSTEMTIME, US_LOCALE, UTCTIME
    {{TIMESTAMP:FORMAT+OFFSET}}             razmak u mikrosekundama, može biti negativan
    {{KEY:qualifier}}                       uloga je opcionalna
    {{KEY:qualifier:role}}
    {{KEY:qualifier[:role]+OFFSET}}         brojčani raznak, moze biti negativan
    {{KEY:qualifier[:role]+SEQ(channel)}}   sekvencijalno povecavanje, resetira se svaki napad
    {{KEY:qualifier[:role]+GSEQ(channel)}}  sekvencijalno povecavanje, traje kroz cijeli scenarij
    {{KEY:qualifier[:role]+RAND[min,max]}}         nasumicni int, cachiran jednom po napadu
    {{KEY:qualifier[:role]+RAND[min,max,step]}}    isto, ali vrijednost mora biti visekratnik step-a

Ako se placeholder ne moze razrijesiti (neispravna sintaksa, nedostaje u topologiji, nepoznat TIMESTAMP format, ili bazna vrijednost nije brojcana
tamo gdje mora biti), generacija se odmah zaustavlja i ispisuje se razlog.

Svaki log u predlosku mora imati polje "hostname" (uz "log_source" i "raw"),
npr. "hostname": "{{COMPUTERNAME:target}}". Ako nedostaje ili se ne moze razrijesiti, generacija se zaustavlja.

Usage:
    python paralog_generator.py <attack_scenario.json> [output_dir]
"""

import json
import re
import sys
import random
import zipfile
from pathlib import Path
from datetime import datetime, timezone, timedelta


# Konstante / regexi

PLACEHOLDER_RE = re.compile(r'\{\{([^{}]+)\}\}')

TIMESTAMP_RE = re.compile(
    r'^TIMESTAMP:(?P<format>[A-Z_]+)(?:\+(?P<offset>-?\d+))?$'
)

MODIFIER_RE = re.compile(
    r'^(?P<left>.*?)(?:\+(?:'
    r'(?P<offset>-?\d+)'
    r'|GSEQ\((?P<gseq_channel>[^)]*)\)'
    r'|SEQ\((?P<seq_channel>[^)]*)\)'
    r'|RAND\[(?P<rand_range>[^\]]*)\]'
    r'))?$'
)


class ScenarioError(Exception):
    """Greska u podacima scenarija koja zaustavlja cijelu generaciju."""


# Topologija

def shrink_machine_dictionary(object: dict) -> dict:
    """
    Spljosti zapis mreze u rjecnik po strojevima:
        machine_data[placeholder] = vrijednost placeholdera
        machine_data["__per_template__"][napad][placeholder] = vrijednost placeholdera (za pojedinu instancu napada)

    Kljucevi koji pocinju s "_" (npr. "_comment") i kljuc "name" se preskacu, name je posebni naziv stroja.
    "per_template" se namjerno NE spljostava zajedno sa svim ostalim, placeholderi ovisni o konkretnoj instanci svakog napada moraju ostati u svom vlastitom prostoru imena, inace bi dva napada imali konflikte s vrijednostima.
    """
    machine_data = {}
    per_template_found = False

    def recurse(obj):
        nonlocal per_template_found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "name" or k.startswith("_"):
                    continue
                if k == "per_template":
                    if k == "per_template" and not per_template_found:
                        machine_data["__per_template__"] = v
                        per_template_found = True
                    continue
                if isinstance(v, dict):
                    recurse(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            recurse(item)
                else:
                    machine_data[k] = v
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(object)
    return machine_data


def make_topology_dict(topology: dict) -> dict:
    """lookup[machine_name] -> spljosteni dictionary stroja."""
    machine_dict = {}
    for machine in topology.get("machines", []):
        name = machine.get("name")
        if name:
            machine_dict[name] = shrink_machine_dictionary(machine)
    return machine_dict


def lookup_placeholder(machines_dictionary: dict, machine_name: str, attack_name: str, placeholder: str):
    """Vraca (vrijednost, poruka_greske), samo jedno od dvoje je None.
    Prvo se provjerava per_template za ovaj napad, zatim opca polja stroja."""
    machine = machines_dictionary.get(machine_name)
    if machine is None:
        return None, f"stroj '{machine_name}' nije pronaden u topologiji"

    per_template = machine.get("__per_template__", {})
    attack_dict = per_template.get(attack_name)
    if attack_dict and placeholder in attack_dict:
        return attack_dict[placeholder], None

    if placeholder in machine:
        return machine[placeholder], None

    return None, f"'{placeholder}' nije pronaden za '{machine_name}' (napad '{attack_name}')"


# Provjera machine_map <-> machines

def validate_machine_map(attack: dict, template: dict):
    """
    Skup kljuceva machine_map mora se tocno podudarati sa skupom iz template['machines'].
    Inace placeholderi u predlosku ne mogu biti razrijeseni.
    """
    declared = set(template.get("machines", []))
    mapped = set(attack.get("machine_map", {}).keys())
    if declared == mapped:
        return

    raise ScenarioError(
        f"Napad '{attack.get('name')}': machine_map se ne podudara sa strojevima u predlosku; "
    )


# Vrijeme

def parse_start_time(start_time_str: str) -> datetime:
    """Parsira pocetno vrijeme. 'current' postavlja trenutno UTC vrijeme."""
    if start_time_str == "current":
        return datetime.now(timezone.utc)
    s = start_time_str
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r'(\.\d{6})\d+', r'\1', s)  # zadrzi samo 6 decimala (mikrosekunde)
    return datetime.fromisoformat(s)


def add_microseconds(dt: datetime, offset_us: int) -> datetime:
    return dt + timedelta(microseconds=offset_us)


def format_iso(dt: datetime) -> str:
    """Windows XML timestamp format sa 6 decimalnih mjesta (SystemTime)."""
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{dt.microsecond:06d}000Z"


def format_us_locale(dt: datetime) -> str:
    """Windows KV log format MM/DD/YYYY HH:MM:SS AM/PM."""
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def format_sysmon_utc(dt: datetime) -> str:
    """Sysmon UtcTime format: GGGG-MM-DD SS:MM:SS.mmm."""
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


TIMESTAMP_FORMATTERS = {
    "SYSTEMTIME": format_iso,
    "US_LOCALE": format_us_locale,
    "UTCTIME": format_sysmon_utc,
}


# Nasumicni brojevi

def generate_random_number(range_str: str) -> str:
    """
    Generira nasumicni broj iz raspona "min,max" ili "min,max,step" (zagrade su vec skinute regexom). 
    Ako je step zadan, vrijednost mora biti visekratnik step-a.
    """
    try:
        parts = [p.strip() for p in range_str.split(",")]
        low, high = int(parts[0]), int(parts[1])
        step = int(parts[2]) if len(parts) > 2 else 1
        if step > 1:
            remainder = low % step
            if remainder:
                low += step - remainder  # poravnaj donju granicu na visekratnik step-a
        return str(random.randrange(low, high + 1, step))
    except Exception as e:
        raise ValueError(f"neispravan format raspona '[{range_str}]': {e}")


# Parsiranje placeholdera

def parse_placeholder(content: str) -> dict:
    """Rastavlja sadrzaj {{...}} u strukturu. Baca ValueError ako placeholder nije u pravilnom formatu."""
    is_timestamp = TIMESTAMP_RE.match(content)
    if is_timestamp:
        return {
            "kind": "timestamp",
            "format": is_timestamp.group("format"),
            "offset": int(is_timestamp.group("offset") or 0),
        }

    parts = content.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"ocekivano KEY:qualifier[:role][+modifikator], dobiveno '{{{{{content}}}}}'")
    key, rest = parts

    m = MODIFIER_RE.match(rest)
    if not m:
        raise ValueError(f"ne mogu parsirati qualifier/role/modifikator u '{{{{{content}}}}}'")

    left = m.group("left")
    qr = left.split(":", 1)
    qualifier = qr[0]
    role = qr[1] if len(qr) > 1 else None
    if not qualifier:
        raise ValueError(f"nedostaje qualifier u '{{{{{content}}}}}'")

    if m.group("offset") is not None:
        return {"kind": "offset", "key": key, "qualifier": qualifier, "role": role,
                "offset": int(m.group("offset"))}
    if m.group("gseq_channel") is not None:
        return {"kind": "gseq", "key": key, "qualifier": qualifier, "role": role,
                "channel": m.group("gseq_channel")}
    if m.group("seq_channel") is not None:
        return {"kind": "seq", "key": key, "qualifier": qualifier, "role": role,
                "channel": m.group("seq_channel")}
    if m.group("rand_range") is not None:
        return {"kind": "rand", "key": key, "qualifier": qualifier, "role": role,
                "range": m.group("rand_range")}
    return {"kind": "plain", "key": key, "qualifier": qualifier, "role": role}


def topology_key(parsed: dict) -> str:
    """Tocan kljuc za pretragu u topologiji: KEY, ili KEY:role ako je role
    zadan, s tim da GSEQ/SEQ modifikator ostaje dio kljuca (bazna vrijednost
    je vezana uz taj kanal), dok se literalni offset ne ukljucuje (ista
    bazna vrijednost dijeli se izmedu razlicitih offseta)."""
    key = parsed["key"]
    role = parsed.get("role")
    key_role = f"{key}:{role}" if role else key
    if parsed["kind"] == "gseq":
        return f"{key_role}+GSEQ({parsed['channel']})"
    if parsed["kind"] == "seq":
        return f"{key_role}+SEQ({parsed['channel']})"
    return key_role


# Obrada napada

def process_attack(attack: dict, template: dict, lookup: dict,
                    attack_start: datetime, gseq_state: dict):
    """
    Razrjesava sve logove iz template['logs'] redom kako su navedeni.
    Vraca listu (log_source, razrijeseni_raw, log_id, hostname) tuplova.

    gseq_state se dijeli izmedu svih napada u scenariju (prosljeduje se izvana).
    seq_state i rand_cache su lokalni: SEQ se resetira, a RAND se ponovno generira za svaki poziv (svaki napad).

    per_template u topologiji trazi se po imenu napada (attack["name"]), ne po nazivu datoteke predloska - vise napada moze dijeliti isti predlozak (isti template file) uz razlicite per_template vrijednosti.
    """
    validate_machine_map(attack, template)

    machine_map = attack.get("machine_map", {})
    attack_name = attack["name"]

    seq_state = {}
    rand_cache = {}
    results = []

    for log_entry in template.get("logs", []):
        log_id = log_entry["id"]
        raw = log_entry["raw"]
        log_source = log_entry.get("log_source")
        if not log_source:
            raise ScenarioError(
                f"Napad '{attack_name}', log {log_id}: nedostaje 'log_source' polje u predlosku"
            )
        hostname_template = log_entry.get("hostname")
        if not hostname_template:
            raise ScenarioError(
                f"Napad '{attack_name}', log {log_id}: nedostaje 'hostname' polje u predlosku"
            )
        advanced_this_log = set()  # (vrsta, qualifier, key, role, channel) vec odradeni u ovom logu

        def replace(m):
            content = m.group(1)
            try:
                parsed = parse_placeholder(content)
            except ValueError as e:
                raise ScenarioError(
                    f"Napad '{attack_name}', log {log_id}: neispravan placeholder - {e}"
                )

            if parsed["kind"] == "timestamp":
                fmt = parsed["format"]
                formatter = TIMESTAMP_FORMATTERS.get(fmt)
                if formatter is None:
                    raise ScenarioError(
                        f"Napad '{attack_name}', log {log_id}: nepoznat TIMESTAMP format '{fmt}' "
                        f"(ocekivano jedan od: {', '.join(TIMESTAMP_FORMATTERS)}) "
                        f"- placeholder {{{{{content}}}}}"
                    )
                dt = add_microseconds(attack_start, parsed["offset"])
                return formatter(dt)

            key = parsed["key"]
            qualifier = parsed["qualifier"]
            role = parsed["role"]
            resolved_q = machine_map.get(qualifier, qualifier)

            if parsed["kind"] == "rand":
                cache_key = (resolved_q, key, role)
                if cache_key not in rand_cache:
                    try:
                        rand_cache[cache_key] = generate_random_number(parsed["range"])
                    except ValueError as e:
                        raise ScenarioError(
                            f"Napad '{attack_name}', log {log_id}: {e} - placeholder {{{{{content}}}}}"
                        )
                return rand_cache[cache_key]

            topo_key = topology_key(parsed)
            base_val, err = lookup_placeholder(lookup, resolved_q, attack_name, topo_key)
            if err:
                raise ScenarioError(
                    f"Napad '{attack_name}', log {log_id}: {err} - placeholder {{{{{content}}}}}"
                )

            if parsed["kind"] == "plain":
                return str(base_val)

            if parsed["kind"] == "offset":
                try:
                    return str(int(base_val) + parsed["offset"])
                except (TypeError, ValueError):
                    raise ScenarioError(
                        f"Napad '{attack_name}', log {log_id}: bazna vrijednost '{base_val}' za '{topo_key}' "
                        f"nije brojcana, offset {parsed['offset']:+d} se ne moze primijeniti "
                        f"- placeholder {{{{{content}}}}}"
                    )

            if parsed["kind"] in ("seq", "gseq"):
                state = seq_state if parsed["kind"] == "seq" else gseq_state
                counter_key = (resolved_q, key, role, parsed["channel"])
                mark = (parsed["kind"],) + counter_key
                if counter_key not in state:
                    try:
                        state[counter_key] = int(base_val)
                    except (TypeError, ValueError):
                        raise ScenarioError(
                            f"Napad '{attack_name}', log {log_id}: bazna vrijednost '{base_val}' za '{topo_key}' "
                            f"nije brojcana, ne moze se koristiti kao {parsed['kind'].upper()} pocetak "
                            f"- placeholder {{{{{content}}}}}"
                        )
                elif mark not in advanced_this_log:
                    state[counter_key] += 1
                advanced_this_log.add(mark)
                return str(state[counter_key])

            raise ScenarioError(
                f"Napad '{attack_name}', log {log_id}: neobradena vrsta placeholdera "
                f"- placeholder {{{{{content}}}}}"
            )

        resolved_raw = PLACEHOLDER_RE.sub(replace, raw)
        resolved_hostname = PLACEHOLDER_RE.sub(replace, hostname_template)
        if not resolved_hostname.strip():
            raise ScenarioError(
                f"Napad '{attack_name}', log {log_id}: 'hostname' se razrijesio u prazan string"
            )
        results.append((log_source, resolved_raw, log_id, resolved_hostname))

    return results


# Izvoz (grupirano po hostname + log_source, spojeno kroz cijeli scenarij)

def sanitize_for_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')


def write_host_conf(conf_path: Path, hostname: str, techniques: list, descriptions: list,
                     datasets: list):
    """
    datasets: lista (log_source, path) tuplova za taj hostname, redoslijedom
    prvog pojavljivanja. id je stvarni hostname (izvuceno iz "hostname" polja
    predloska), ne generican placeholder.
    """
    lines = [
        "author: Generated",
        f"id: {hostname}",
        f"date: {format_iso(datetime.now(timezone.utc))}",
        f"description: {' | '.join(descriptions)}",
        "environment: attack_range, paralog_generator",
        "directory: ADD_DIR",
        "mitre_technique:",
    ]
    lines += [f"- {t}" for t in techniques]
    lines.append("datasets:")

    for log_source, path in datasets:
        sourcetype = log_source.split(":", 1)[0] if ":" in log_source else log_source
        lines.append(f"- name: {path.stem}")
        lines.append(f"  path: {path.name}")
        lines.append(f"  sourcetype: {sourcetype}")
        lines.append(f"  source: {log_source}")

    with open(conf_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def generate(scenario_path: str, output_dir: str = "."):
    base_dir = Path(scenario_path).parent
    out_dir = Path(output_dir)
    scenario_stem = Path(scenario_path).stem

    with open(scenario_path, encoding="utf-8") as f:
        scenario = json.load(f)

    topology_file = base_dir / scenario["topology"]
    with open(topology_file, encoding="utf-8") as f:
        topology = json.load(f)

    scenario_start = parse_start_time(scenario["start_time"])
    lookup = make_topology_dict(topology)

    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Scenario : {scenario.get('description', '')}")
    print(f"Topology : {topology_file.name}")
    print(f"Start    : {format_iso(scenario_start)}")
    print()

    # (hostname, log_source) -> lista razrijesenih raw stringova, u redoslijedu
    # dodavanja kroz cijeli scenarij (logovi iz razlicitih napada koji dijele
    # isti hostname+log_source zavrsavaju spojeni redoslijedom dodavanja, ne
    # sortirani po vremenu).
    buckets = {}
    # hostname -> {"techniques": [...], "descriptions": [...]} - samo za napade
    # koji su stvarno proizveli barem jedan log za taj hostname, redoslijedom
    # prvog pojavljivanja.
    host_meta = {}
    total_logs = 0
    gseq_state = {}  # dijeli se izmedu svih napada u scenariju

    for attack in scenario.get("attacks", []):
        # time_offset_ms je u milisekundama (naziv polja je tocan) - pretvara
        # se u mikrosekunde jer cijeli generator interno radi u mikrosekundama.
        attack_start = add_microseconds(scenario_start, attack.get("time_offset_ms", 0) * 1000)

        template_file = base_dir / attack["template"]
        with open(template_file, encoding="utf-8") as f:
            template = json.load(f)

        print(f"Attack [{attack['id']}] : {attack['name']} ({attack['technique']})")
        print(f"  Template : {template_file.name}")
        print(f"  T0       : {format_iso(attack_start)}")

        try:
            resolved = process_attack(attack, template, lookup, attack_start, gseq_state)
        except ScenarioError as e:
            print(f"\n[ERROR] {e}")
            print("Generacija zaustavljena - placeholderi se ne mogu pouzdano razrijesiti.")
            sys.exit(1)

        per_bucket_count = {}
        for log_source, raw_text, log_id, hostname in resolved:
            bucket_key = (hostname, log_source)
            buckets.setdefault(bucket_key, []).append(raw_text)
            per_bucket_count[bucket_key] = per_bucket_count.get(bucket_key, 0) + 1
            total_logs += 1

            meta = host_meta.setdefault(hostname, {"techniques": [], "descriptions": []})
            t, d = attack.get("technique", ""), attack.get("description", "")
            if t and t not in meta["techniques"]:
                meta["techniques"].append(t)
            if d and d not in meta["descriptions"]:
                meta["descriptions"].append(d)

        for (hostname, src), count in per_bucket_count.items():
            print(f"  {hostname} / {src}: {count} log(s)")
        print()

    # zapisi jednu log datoteku po (hostname, log_source) grupi
    datasets_by_host = {}  # hostname -> [(log_source, path), ...]
    for (hostname, log_source), lines in buckets.items():
        filename = f"{scenario_stem}_{sanitize_for_filename(hostname)}_{sanitize_for_filename(log_source)}.log"
        path = out_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
                if not line.endswith("\n"):
                    f.write("\n")
        datasets_by_host.setdefault(hostname, []).append((log_source, path))
        print(f"Written  : {path.name} ({len(lines)} log(s), host={hostname}, source={log_source})")

    # zapisi jedan .yml po hostnameu, sa svim datasetima tog hosta
    conf_paths = []
    for hostname, datasets in datasets_by_host.items():
        conf_path = out_dir / f"{scenario_stem}_{sanitize_for_filename(hostname)}.yml"
        meta = host_meta.get(hostname, {"techniques": [], "descriptions": []})
        write_host_conf(conf_path, hostname, meta["techniques"], meta["descriptions"], datasets)
        conf_paths.append(conf_path)
        print(f"Conf file: {conf_path.name}")
    print()

    output_files = [p for ds in datasets_by_host.values() for _, p in ds] + conf_paths
    if len(output_files) > 1:
        zip_path = out_dir / f"{scenario_stem}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in output_files:
                zf.write(f, f.name)
        for f in output_files:
            f.unlink()
        print(f"Vise datoteka - zipano u: {zip_path.name}")
    else:
        print(f"Output: {output_files[0].name if output_files else '(nema izlaza)'}")

    print(f"Ukupno generiranih logova: {total_logs}")


# Main

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python paralog_generator.py <attack_scenario.json> [output_dir]")
        sys.exit(1)

    generate(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ".")
