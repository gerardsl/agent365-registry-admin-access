# Test results

Tests run on November 23, 2026 in a Microsoft lab tenant with Microsoft Agent 365 licenses, against the Microsoft Graph Agent Registration API (beta). Real identifiers aren't included.

## Identities

| Identity | Token type | Microsoft Entra roles / permissions |
|---|---|---|
| **User A** (administrator) | Delegated | First: AI Administrator, Agent ID Administrator, Security Administrator and others, **without** Global Administrator. Then: **Global Administrator** activated in PIM |
| **User B** (test user) | Delegated | First **AI Administrator only**. Then AI Administrator + **Agent Registry Administrator** |
| **App 1** | App-only (certificate) | Application permission `AgentRegistration.ReadWrite.All` |
| **App 2** | App-only (certificate) | Application permission `AgentRegistration.ReadWrite.All` |

In the delegated tests, the token included the `AgentRegistration.ReadWrite.All` permission (*Microsoft Graph Command Line Tools* client). The roles of each test were checked in the token's `wids` claim.

## Registrations

| Registration | Created by | Owners (`ownerIds`) | Managing application (`managedByAppId`) |
|---|---|---|---|
| R_A | User A | User A | — |
| R_B | User B | User B | — |
| R_C1 | App 2 | User A | App 2 |
| R_C2 | App 1 | User A | App 1 |
| Real | Agent 365 connector (Google Vertex AI) | — | M365 App Management Service (Microsoft) |

## Read (GET) and write (PATCH)

The write test is a `PATCH` with an empty body (`{}`). It doesn't change data and returns the same 403 as a real change. Real changes were also made where access was allowed (row 10).

| # | Identity | Registration | Owner? | GET | PATCH |
|---|---|---|---|---|---|
| 1 | User A (AI Administrator, no GA) | R_A | Yes | 200 | 200 |
| 2 | User A (AI Administrator, no GA) | Real | No | **403** | **403** |
| 3 | User A (**Global Administrator**) | Real | No | **403** | **403** |
| 4 | User A (**Global Administrator**) | R_B | No | **403** | **403** |
| 5 | User B (**AI Administrator only**) | R_B | Yes | 200 | 200 |
| 6 | User B (**AI Administrator only**) | R_A, R_C2, Real | No | **403** | **403** |
| 7 | User B (AI Administrator + **Agent Registry Administrator**) | R_A, R_C2, Real | No | **403** | **403** (also 15 minutes later) |
| 8 | **App 1** | R_A, R_B | No (owners are users) | **200** | **200** |
| 9 | **App 1** | R_C2 (managed by App 1) | — | 200 | 200 |
| 10 | **App 1** | R_B: real change of `displayName`, `description` and `ownerIds`, then restore | No | 200 | **200, verified with GET** |
| 11 | **App 1** | R_C1 (managed by App 2) | — | **403** | **403** |
| 12 | **App 1** | Real (managed by a Microsoft service) | — | **403** | **403** |
| 13 | App 2 | R_C1 (managed by App 2) | — | 200 | 200 |
| 14 | User A (Global Administrator) | R_C2, which User A **owns** but App 1 manages | Yes | **403** | **403** |

Error messages returned:

- `403 Access is denied to read the agent registration.` (GET)
- `403 Access is denied to update the agent registration.` (PATCH)

## Creating registrations with a managing application

| Identity | `managedByAppId` | Result |
|---|---|---|
| User A (Global Administrator) | Any application | **403** `Access is denied to create the agent registration.` |
| App 1 | Another application (App 2 or a Microsoft one) | **403** |
| App 1 | Itself | 201 (created) |

## Other observations

| Observation | Detail |
|---|---|
| Registration ID | Equal to its `sourceAgentId` (for example, `my-agent-1`), not a generated GUID |
| List operation | `GET /beta/copilot/agentRegistrations` returns 404: it doesn't exist |
| Inventory | For packages with `AgentMetadatas`, the Package Management API (`/beta/copilot/admin/catalog/packages`) returns `SourceAgentId` (= registration ID) and `ManagedBy` (managing application). Its `platform` field is the registration's `originatingStore` |
| Platform change | `PATCH {"originatingStore": "<another value>"}` → **500** `Agent registration not found.` for the owner (users A and B) and for the managing application, both from a value and from empty. The same value returns 200. `displayName`, `description` and `ownerIds` can be changed |
| Copilot Studio, Agent 365 SDK/CLI and Foundry agents | They appear in the inventory (managed by Power Virtual Agents Service, Agent 365 and Azure Machine Learning). With their `SourceAgentId`, the Agent Registration API returns 404 (Copilot Studio, Agent 365) or 400 (Foundry, because the ID contains `/`) |
| Throttling | With dozens of calls in a row: `429 The request was throttled by a downstream service. Retry the request later.` |
| `PATCH {}` | 200 with no change to the registration when the identity has access; 403 when it doesn't |

## Conclusion

- With delegated access, only the owner can read or update a registration without a managing application. No Microsoft Entra role extends this: AI Administrator, Agent Registry Administrator and Global Administrator were tested.
- An app-only application with `AgentRegistration.ReadWrite.All` can read and update all registrations without a managing application, whoever their owners are.
- Registrations with a managing application can only be read and updated by that application.
