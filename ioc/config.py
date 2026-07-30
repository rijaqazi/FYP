import os

# Server Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLES_DIR = os.path.join(BASE_DIR, "stix_output")

# Medallion Configuration
CONFIG = {
    "backend": {
        "module": "medallion.backends.memory_backend",
        "module_class": "MemoryBackend",
        "uri": "mongodb://localhost:27017/",  # Memory backend use karenge
    },
    "users": {
        "admin": {
            "password": "password123",
            "role": "admin"
        },
        "user": {
            "password": "user123",
            "role": "user"
        }
    },
    "taxii": {
        "max_page_size": 100
    },
    "auth": {
        "module": "medallion.auth.basic_auth_module",
        "module_class": "BasicAuthModule"
    }
}

# Collections Configuration
COLLECTIONS = [
    {
        "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        "title": "IOC Collection",
        "description": "Main collection for sharing IOCs and STIX bundles",
        "can_read": True,
        "can_write": True,
        "media_types": ["application/stix+json;version=2.1"]
    },
    {
        "id": "e9b5a5a5-1234-5678-90ab-cdef12345678", 
        "title": "Malware Indicators",
        "description": "Collection for malware related IOCs",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"]
    }
]
