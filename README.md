[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline--v4--service-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-v4-service)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-base)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-base)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-v4-service)](./LICENSE.md)

# Assemblyline 4 - Service Base

This repository provides the base service functionality for Assemblyline 4 services.

## Image variants and tags

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Creating a new Assemblyline service

You can create a new Assemblyline service by using this [template](https://github.com/CybercentreCanada/assemblyline-service-template):

```bash
apt install jq
pip install git+https://github.com/CybercentreCanada/assemblyline-service-template.git
cruft create https://github.com/CybercentreCanada/assemblyline-service-template.git
```

## Documentation

For more information about service development for Assemblyline, follow this [guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/developing_an_assemblyline_service/).

---

# Assemblyline 4 - Service Base

Ce référentiel fournit les fonctionnalités de base des services Assemblyline 4.

## Créer un nouveau service Assemblyline

Vous pouvez créer un nouveau service Assemblyline en utilisant ce [template](https://github.com/CybercentreCanada/assemblyline-service-template).

## Variantes et étiquettes d'image

| **Type d'étiquette** | **Description**                                                                                                  |  **Exemple d'étiquette**   |
| :------------------: | :--------------------------------------------------------------------------------------------------------------- | :------------------------: |
|       dernière       | La version la plus récente (peut être instable).                                                                 |          `latest`          |
|      build_type      | Le type de compilation utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` or `dev`      |
|        séries        | Le détail de compilation utilisé, incluant la version et le type de compilation : `version.buildType`.           | `4.5.stable`, `4.5.1.dev3` |

```bash
apt install jq
pip install git+https://github.com/CybercentreCanada/assemblyline-service-template.git
cruft create https://github.com/CybercentreCanada/assemblyline-service-template.git
```

## Documentation

Pour plus d'informations sur le développement des services pour Assemblyline, suivez ce [guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/developing_an_assemblyline_service/).
