## 1. Présentation

Ce projet met en œuvre un pipeline complet de détection, d'analyse et de
réponse aux incidents de sécurité (SOC), adapté au contexte métier d'une
banque d'investissement / société de gestion d'actifs marocaine
(CDG Capital, pris comme cas d'application).

📄 **Commencez par lire `docs/analyse_du_sujet.md`** pour le cadrage complet
du sujet et les choix d'architecture justifiés.

## 2. Architecture

![Architecture SIEM/SOAR](architecture/architecture_siem_soar.png)

*(schéma source éditable : `architecture/generate_diagram.py`, version
vectorielle : `architecture/architecture_siem_soar.svg`)*

| Brique | Rôle | Technologie |
|---|---|---|
| Collecte + SIEM | Détection, corrélation, active-response | **Wazuh** (manager, indexer, dashboard) |
| Gestion de cas | Registre d'incidents / investigation | **TheHive** |
| Enrichissement | Réputation IP / hash / domaine | **Cortex** |
| Orchestration (SOAR) | Exécution des playbooks de réponse | **Orchestrateur Python/Flask maison** |

## 3. Structure du projet

```
soc-project/
├── docker-compose.siem.yml       # Stack SIEM (Wazuh)
├── docker-compose.soar.yml       # Stack SOAR (TheHive + Cortex + orchestrateur)
├── generate-indexer-certs.yml    # Génération des certificats (étape 1)
├── config/                       # Configuration Wazuh (indexer, dashboard, certs)
│   └── wazuh_cluster/wazuh_manager.conf   # Règles/active-response/intégration webhook
├── wazuh/custom_rules/local_rules.xml     # Règles de détection personnalisées CDG Capital
├── soar-orchestrator/            # Orchestrateur SOAR (webhook + moteur de playbooks)
│   ├── app.py
│   ├── lib/                      # Clients TheHive, Cortex, notifications, moteur
│   └── playbooks/                # 4 playbooks YAML (PB-01 à PB-04)
├── architecture/                 # Schéma d'architecture (source + PNG/SVG)
└── docs/
    ├── analyse_du_sujet.md       # Cadrage et justification des choix
    ├── matrice_cas_usage.md      # Cas d'usage détection/réponse ↔ MITRE ATT&CK
    └── scenarios_de_test.md      # Scénarios de test pour la démonstration
```

## 4. Prérequis (poste de stage)

- Docker + Docker Compose v2 (`docker compose version`)
- **8 Go de RAM minimum** disponibles pour Docker (Wazuh + TheHive/Cortex
  sont gourmands ; 16 Go recommandés si vous gardez tout allumé en même temps)
- Linux (natif ou WSL2 sous Windows) recommandé
- Sur Linux : augmenter `vm.max_map_count` pour OpenSearch/Elasticsearch :
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  # rendre permanent :
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
  ```

## 5. Installation — Étape par étape

### 5.1. Génération des certificats (obligatoire avant le premier démarrage)

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 5.2. Démarrage du SIEM (Wazuh)

```bash
docker compose -f docker-compose.siem.yml up -d
```

Patientez ~2-3 minutes puis accédez au dashboard :
👉 `https://localhost` (utilisateur : `admin` / mot de passe : `SecretPassword`
— **à changer immédiatement**, voir `config/wazuh_indexer/internal_users.yml`)

### 5.3. Chargement des règles personnalisées

```bash
docker cp wazuh/custom_rules/local_rules.xml \
  $(docker ps -qf "name=wazuh.manager"):/var/ossec/etc/rules/local_rules.xml
docker exec $(docker ps -qf "name=wazuh.manager") /var/ossec/bin/wazuh-control restart
```

### 5.4. Démarrage du SOAR (TheHive + Cortex + orchestrateur)

```bash
docker compose -f docker-compose.soar.yml up -d --build
```

Accès :
- TheHive : `http://localhost:9000` (créer l'organisation + utilisateur au 1er lancement)
- Cortex : `http://localhost:9001` (créer le compte admin, configurer les analyseurs,
  générer une clé API)
- Orchestrateur SOAR : `http://localhost:5000/health`

### 5.5. Finaliser l'intégration

1. Dans TheHive, générer une clé API et la reporter dans
   `docker-compose.soar.yml` → `THEHIVE_API_KEY` du service `soar-orchestrator`.
2. Dans Cortex, créer une organisation, activer l'analyseur `AbuseIPDB` (clé API
   gratuite sur abuseipdb.com) et reporter la clé Cortex dans `CORTEX_API_KEY`.
3. Redémarrer l'orchestrateur : `docker compose -f docker-compose.soar.yml up -d --build soar-orchestrator`
4. Vérifier que les playbooks sont bien chargés :
   ```bash
   curl http://localhost:5000/playbooks
   ```

### 5.6. Installer un agent Wazuh (source de logs)

Suivre l'assistant intégré : Wazuh Dashboard → **Agents** → **Add agent**,
choisir l'OS de la machine à surveiller (Windows/Linux) et suivre les
commandes générées automatiquement. C'est la source d'événements qui
alimentera les règles personnalisées.

## 6. Tester le pipeline complet

Voir `docs/scenarios_de_test.md` pour 4 scénarios prêts à l'emploi
(bruteforce, ransomware, exfiltration, compromission de compte) qui
valident la chaîne détection → alerte → SOAR → réponse automatisée →
notification, de bout en bout.

## 7. Pour la rédaction du rapport de stage

Ce dépôt fournit déjà la matière technique. Pour le rapport, il est
recommandé de structurer autour de :
1. Contexte et enjeux cybersécurité du secteur financier marocain
2. État de l'art SIEM/SOAR (comparatif d'outils, justification des choix — `docs/analyse_du_sujet.md`)
3. Conception de l'architecture (schéma + choix techniques)
4. Mise en œuvre (extraits de configuration commentés)
5. Cas d'usage et détection (matrice MITRE ATT&CK — `docs/matrice_cas_usage.md`)
6. Tests et validation (scénarios + captures d'écran + mesures MTTD/MTTR — `docs/scenarios_de_test.md`)
7. Bilan, limites (environnement de lab vs. production réelle) et perspectives
