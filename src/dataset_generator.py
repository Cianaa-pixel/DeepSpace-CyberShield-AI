import pandas as pd
import random
from datetime import datetime, timedelta

# ==========================================================
# DeepSpace CyberShield AI
# Realistic Dataset Generator
# Version 1
# ==========================================================

NUM_RECORDS = 1000

# ==========================================================
# Mission Profiles
# ==========================================================

MISSION_PROFILES = {

    "Mars_Rover": {
        "relay": "Relay_A",
        "delay": (1180,1250),
        "signal": (-73,-70),
        "ttl": (60,64)
    },

    "Orbiter_1": {
        "relay": "Relay_B",
        "delay": (1250,1350),
        "signal": (-72,-68),
        "ttl": (60,64)
    },

    "Lunar_Probe": {
        "relay": "Relay_C",
        "delay": (900,1050),
        "signal": (-68,-64),
        "ttl": (60,64)
    },

    "DeepSpace_Satellite": {
        "relay": "Relay_D",
        "delay": (1800,2500),
        "signal": (-82,-76),
        "ttl": (58,64)
    },

    "ISS_Module": {
        "relay": "Relay_E",
        "delay": (450,650),
        "signal": (-60,-55),
        "ttl": (62,64)
    }

}

# ==========================================================
# Attack Profiles
# ==========================================================

ATTACK_PROFILES = {

    "Normal":{
        "delay_factor":1.0,
        "signal_boost":0,
        "ttl_drop":0,
        "relay":"Trusted"
    },

    "Spoofing":{
        "delay_factor":0.35,
        "signal_boost":45,
        "ttl_drop":12,
        "relay":"Unknown_Relay"
    },

    "Replay":{
        "delay_factor":3.8,
        "signal_boost":-15,
        "ttl_drop":20,
        "relay":"Trusted"
    },

    "Injection":{
        "delay_factor":0.55,
        "signal_boost":50,
        "ttl_drop":25,
        "relay":"Relay_X"
    }

}

# ==========================================================
# Mission Phases
# ==========================================================

MISSION_PHASES = [

    "Launch",
    "Cruise",
    "Orbit",
    "Landing",
    "Surface Operation",
    "Sample Collection",
    "Data Transmission",
    "Return Mission"

]

# ==========================================================
# Communication Bands
# ==========================================================

FREQUENCY_BANDS = [

    "S-Band",
    "X-Band",
    "Ka-Band"

]

# ==========================================================
# Encryption
# ==========================================================

ENCRYPTION_TYPES = [

    "AES-256",
    "RSA-4096",
    "Post-Quantum"

]

# ==========================================================
# Packet Sizes
# ==========================================================

PACKET_SIZES = [

    512,
    1024,
    2048,
    4096

]

print("="*50)
print("DeepSpace CyberShield AI")
print("="*50)
print("Mission Profiles Loaded :",len(MISSION_PROFILES))
print("Attack Profiles Loaded :",len(ATTACK_PROFILES))
print("Mission Phases :",len(MISSION_PHASES))
print("Communication Bands :",len(FREQUENCY_BANDS))
print("Encryption Types :",len(ENCRYPTION_TYPES))
print("Packet Sizes :",len(PACKET_SIZES))
print("="*50)
# ==========================================================
# Utility Functions
# ==========================================================

def generate_timestamp(start_time, index):
    return start_time + timedelta(seconds=index * random.randint(5, 20))


def generate_status():

    return random.choices(

        ["Normal", "Spoofing", "Replay", "Injection"],

        weights=[80, 7, 7, 6],

        k=1

    )[0]


def generate_packet_size():
    return random.choice(PACKET_SIZES)


def generate_band():
    return random.choice(FREQUENCY_BANDS)


def generate_encryption():
    return random.choice(ENCRYPTION_TYPES)


def generate_phase():
    return random.choice(MISSION_PHASES)


# ==========================================================
# Trust Functions (Research Paper)
# ==========================================================

def calculate_ttl_evidence(ttl):

    return round((ttl / 64) * 100, 2)


def calculate_dsslv(signal):

    score = 100 - abs(signal + 70)

    score = max(0, min(score, 100))

    return round(score, 2)


def calculate_dynamic_ttl_trust(ttl):

    trust = ttl * 1.5

    trust = max(0, min(trust, 100))

    return round(trust, 2)


def calculate_final_trust(ttl_score, dsslv):

    return round((ttl_score * 0.5) + (dsslv * 0.5), 2)


# ==========================================================
# Dataset Creation
# ==========================================================

rows = []

start_time = datetime(2026, 7, 15, 10, 0, 0)

for i in range(NUM_RECORDS):

    source = random.choice(list(MISSION_PROFILES.keys()))

    profile = MISSION_PROFILES[source]

    attack = generate_status()

    timestamp = generate_timestamp(start_time, i)

    relay = profile["relay"]

    delay = random.randint(profile["delay"][0], profile["delay"][1])

    signal = random.randint(profile["signal"][0], profile["signal"][1])

    ttl = random.randint(profile["ttl"][0], profile["ttl"][1])

    if attack != "Normal":

        attack_profile = ATTACK_PROFILES[attack]

        relay = attack_profile["relay"]

        delay = int(delay * attack_profile["delay_factor"])

        signal += attack_profile["signal_boost"]

        ttl -= attack_profile["ttl_drop"]

        ttl = max(ttl, 0)

    ttl_evidence = calculate_ttl_evidence(ttl)

    dsslv_score = calculate_dsslv(signal)

    dynamic_ttl = calculate_dynamic_ttl_trust(ttl)

    trust_score = calculate_final_trust(dynamic_ttl, dsslv_score)

    rows.append([

        timestamp,

        source,

        "Earth",

        relay,

        generate_phase(),

        generate_band(),

        generate_encryption(),

        generate_packet_size(),

        delay,

        signal,

        ttl,

        ttl_evidence,

        dsslv_score,

        dynamic_ttl,

        trust_score,

        attack

    ])
    # ==========================================================
# Create DataFrame
# ==========================================================

dataset = pd.DataFrame(rows, columns=[

    "timestamp",
    "source",
    "destination",
    "relay",
    "mission_phase",
    "frequency_band",
    "encryption",
    "packet_size",
    "delay_ms",
    "signal_strength",
    "ttl",
    "ttl_evidence",
    "dsslv_score",
    "dynamic_ttl_trust",
    "trust_score",
    "status"

])

# ==========================================================
# Save Dataset
# ==========================================================

dataset.to_csv(
    "dataset/communication_logs.csv",
    index=False
)

# ==========================================================
# Statistics
# ==========================================================

print("\n==============================================")
print(" DeepSpace CyberShield AI Dataset Generated ")
print("==============================================")

print(f"Total Records      : {len(dataset)}")
print(f"Normal             : {(dataset['status']=='Normal').sum()}")
print(f"Spoofing           : {(dataset['status']=='Spoofing').sum()}")
print(f"Replay             : {(dataset['status']=='Replay').sum()}")
print(f"Injection          : {(dataset['status']=='Injection').sum()}")

print("\nAverage Trust Score")
print(round(dataset["trust_score"].mean(),2))

print("\nDataset Saved Successfully!")

print("Location : dataset/communication_logs.csv")

print("==============================================")