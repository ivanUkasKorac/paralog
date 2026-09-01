# Paralog Generator + Splunk Lab

Ovaj projekt služi za generiranje parametriziranih sigurnosnih logova i njihovo slanje u Splunk SIEM.

Glavne komponente su:

- Docker laboratorij sa Splunk i Kali Linux kontejnerima
- `paralog_generator_v4.py` za generiranje logova
- `run_replays.py` za automatsko slanje generiranih logova u Splunk

---

## 1. Docker laboratorij

Laboratorij se sastoji od dva Docker servisa:

- **splunk** – Splunk SIEM koji prima i indeksira logove
- **attacker** – Kali Linux kontejner s instaliranim `attack_data`, `security_content` i alatima potrebnim za replay

Docker Compose oba kontejnera stavlja u istu internu mrežu.
```

### Struktura

```text
splunk-lab/
├── compose.yaml
├── attacker/
│   └── Dockerfile
└── splunk/
    ├── Dockerfile
    └── props.conf
```

`props.conf` se koristi kako bi Splunk za Windows XML logove kao `_time` koristio vrijeme samog događaja.

---

## 2. Postavljanje i pokretanje Dockera

Prije početka potrebno je ulogirati se u Splunk (admin:Splunk123!) i dodati index:
•	Settings -> indexes -> New Index -> Name:test (ili drugačije ako se šalje na drugi index) -> Save

Iz direktorija `splunk-lab`:

```bash
sudo docker-compose up -d --build
```

Ako se koristi novija Docker Compose sintaksa:

```bash
sudo docker compose up -d --build
```

Provjera statusa:

```bash
sudo docker-compose ps
```

Ulazak u Kali kontejner:

```bash
sudo docker-compose exec attacker bash
```

Ulazak u Splunk kontejner:

```bash
sudo docker-compose exec splunk bash
```

Splunk Web:

```text
http://localhost:8000
```

U konfiguraciji laboratorija koriste se i:

```text
8000  - Splunk Web
8088  - HEC
9997  - Splunk receiver (nije potreban)
```

Za provjeru ispravnog rada HEC-a:

```bash
curl -k https://localhost:8088/services/collector/event \
-H "Authorization: Splunk mysplunktoken123" \
-H "Content-Type: application/json" \
-d '{"event": "Hello Splunk from Docker!"}'
```

Očekivani rezultat je Success. Možda je potrebno nekoliko minuta dok se ne pokrene.


### Zaustavljanje laboratorija

Za svakodnevni rad:

```bash
sudo docker-compose stop
```

Ponovno pokretanje:

```bash
sudo docker-compose start
```

> `docker-compose down` uklanja kontejnere. Budući da ova konfiguracija ne koristi Docker volumene, time se mogu izgubiti indeksirani Splunk podaci i druge promjene napravljene unutar kontejnera.

---

# 3. Paralog Generator

`paralog_generator_v4.py` generira sigurnosne logove iz definiranog scenarija napada.

Generator koristi:

- JSON datoteku scenarija
- mrežnu topologiju
- JSON predloške napada
- parametre i placeholdere unutar predložaka

Generator zamjenjuje placeholdere vrijednostima definiranima u topologiji i scenariju.

Podržani su i:

```text
{{TIMESTAMP:FORMAT}}                    FORMAT moze biti SYSTEMTIME, US_LOCALE, UTCTIME
{{TIMESTAMP:FORMAT+OFFSET}}             razmak u mikrosekundama, može biti negativan
{{KEY:qualifier}}                       uloga je opcionalna
{{KEY:qualifier:role}}
{{KEY:qualifier[:role]+OFFSET}}         brojčani raznak, moze biti negativan
{{KEY:qualifier[:role]+SEQ(channel)}}   sekvencijalno povecavanje, resetira se svaki napad
{{KEY:qualifier[:role]+GSEQ(channel)}}  sekvencijalno povecavanje, traje kroz cijeli scenarij
{{KEY:qualifier[:role]+RAND[min,max]}}         nasumicni int, cachiran jednom po napadu
{{KEY:qualifier[:role]+RAND[min,max,step]}}    isto, ali vrijednost mora biti visekratnik step-a
```

### Pokretanje

```bash
python3 paralog_generator_v4.py <attack_scenario.json> [output_dir]
```

Primjer:

```bash
python3 paralog_generator_v4.py attack_scenario.json output
```

Ako postoji više izlaznih datoteka, generator ih automatski sprema u ZIP arhivu, primjerice:

```text
attack_scenario.zip
```

Svaki generirani host dobiva vlastitu `.yml` konfiguraciju i pripadajuće `.log` datoteke.

### Napomena

Svaki log u templateu mora imati:

```json
"hostname"
"log_source"
"raw"
```

Ako generator ne može razriješiti neki placeholder ili nedostaje potrebna vrijednost iz topologije, izvođenje se prekida kako se ne bi generirali nekonzistentni logovi.

---

# 4. Run Replays

`run_replays.py` služi za automatsko slanje svih generiranih datasetova u Splunk koristeci replay.py od attack data.

Skripta pronalazi sve `.yml` datoteke u direktoriju scenarija i za svaku pokreće Splunkov:

```text
replay.py
```

### Sintaksa

```bash
python3 run_replays.py <path_to_replay.py> <scenario_dir> [--index INDEX]
```

Primjer unutar Kali kontejnera:

```bash
python3 run_replays.py \
    /opt/attack_data/bin/replay.py \
    /root/attack_scenario \
    --index test
```

Ako se `--index` ne navede, koristi se:

```text
test
```

Skripta prekida izvođenje ako neki od replayeva završi s greškom.

---

## 5. Tipičan workflow

Pokreni Docker:

```bash
cd splunk-lab
sudo docker-compose up -d --build
```

Generiraj logove:

```bash
python3 paralog_generator_v4.py attack_scenario.json output
```

Kopiraj ZIP i replay skriptu u Kali kontejner:

```bash
sudo docker cp output/attack_scenario.zip kali-attacker:/root/
sudo docker cp run_replays.py kali-attacker:/root/
```

Uđi u Kali:

```bash
sudo docker-compose exec attacker bash
```

Ako `unzip` nije instaliran:

```bash
apt update
apt install -y unzip
```

Raspakiraj scenarij:

```bash
cd /root
unzip attack_scenario.zip -d attack_scenario
```

Pošalji sve logove u Splunk:

```bash
python3 run_replays.py \
    /opt/attack_data/bin/replay.py \
    /root/attack_scenario \
    --index test
```

Zatim se logovi mogu pregledati u Splunku, primjerice:

```spl
index=test
```

---

## Korisne napomene

- Kod `docker-compose exec` koristi se naziv servisa `attacker`, a ne `container_name` `kali-attacker`.
- `.yml` i pripadajuće `.log` datoteke moraju ostati zajedno u istom direktoriju tijekom replaya.
