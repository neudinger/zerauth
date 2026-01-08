cargo build
cargo build --release 
<!--  produces a static library (libstark_password_proof.a). -->
cc check_ffi.c target/release/libstark_password_proof.a -lpthread -ldl -lm -o check_ffi && ./check_ffi
cargo check
cargo test
wasm-pack build --target web
python3 -m http.server 8000



```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser (Client)
    participant WASM (Rust)
    participant Server / DB

    note over User, Server / DB: Phase 1: Registration (Setup)

    User->>Browser: Enters "Password"
    Browser->>Browser: Generate Random Salt (64-bit)
    Browser->>WASM: get_commitment(Password, Salt)
    
    activate WASM
    WASM->>WASM: Argon2(Password, Salt) -> Secret
    WASM->>WASM: Poseidon(Secret) -> Commitment
    WASM-->>Browser: Returns Commitment
    deactivate WASM

    Browser->>Server / DB: Store (Commitment, Salt)
    Server / DB-->>Browser: Registration Success

    note over User, Server / DB: Phase 2: Login (Proving)

    User->>Browser: Click "Login"
    Browser->>Server / DB: Request Challenge
    Server / DB-->>Browser: Send Nonce (Random 64-bit)
    
    Browser->>WASM: prove_password(Password, Salt, Nonce)
    activate WASM
    WASM->>WASM: Argon2(Password, Salt) -> Secret
    WASM->>WASM: Generate Trace (x -> x^2 + 5)
    WASM->>WASM: Build Merkle Tree (Commit to Trace)
    WASM->>WASM: STARK Prover (Fri, Deep, etc.)
    WASM-->>Browser: Returns Proof (Bytes)
    deactivate WASM

    Browser->>Browser: Serialize Proof (Postcard)

    note over User, Server / DB: Phase 3: Verification

    Browser->>Server / DB: Submit (Proof, Nonce)
    
    note right of Server / DB: *Usually done on Server,*<br/>*but WASM demo does it locally*
    
    Server / DB->>Server / DB: Fetch Stored Commitment
    Server / DB->>WASM: verify_password_proof(Proof, Commitment, Nonce)
    
    activate WASM
    WASM->>WASM: Check Constraints & Merkle Paths
    WASM->>WASM: Check Public Inputs (Commitment, Nonce)
    WASM-->>Server / DB: Returns true/false
    deactivate WASM

    alt is Valid
        Server / DB-->>User: Login Success!
    else is Invalid
        Server / DB-->>User: Access Denied.
    end
```


```mermaid
architecture-beta
    group browser(logos:chrome)[Browser Sandbox]
    
    service user(internet)[User Input]
    
    service js(logos:javascript)[JS Controller] in browser
    service wasm(logos:rust)[WASM ZK Core] in browser
    
    service db(database)[Remote Database]

    user:R -- L:js
    js:R -- L:wasm
    js:B -- T:db
```


```mermaid
graph TD
    %% --- STYLE DEFINITIONS ---
    classDef client fill:#eef2ff,stroke:#4f46e5,stroke-width:2px;
    classDef wasm fill:#fff1f2,stroke:#be123c,stroke-width:2px;
    classDef lib fill:#f0fdf4,stroke:#15803d,stroke-width:1px,stroke-dasharray: 5 5;
    classDef db fill:#fefce8,stroke:#a16207,stroke-width:2px;

    %% --- CLIENT LAYER ---
    subgraph Client ["🖥️ Client (Browser / JS)"]
        UI[User Interface<br/> HTML/CSS]:::client
        JS[JS Controller<br/> State Mgmt]:::client
    end

    %% --- WASM LAYER ---
    subgraph RustWasm ["🦀 Rust WASM Module"]
        direction TB
        
        subgraph PublicAPI ["Public API (wasm_bindgen)"]
            FnCommit[get_commitment]:::wasm
            FnProve[prove_password]:::wasm
            FnVerify[verify_password_proof]:::wasm
        end

        subgraph CoreLogic ["Internal Logic & Dependencies"]
            Argon2Lib[crate: rust-argon2]:::lib
            PoseidonLib[crate: Poseidon2]:::lib
            
            subgraph ZKEngine ["Plonky3 ZK Engine"]
                TraceGen[Trace Generator<br/> x → x² + 5]:::lib
                AirDef[AIR Constraints]:::lib
                P3Prover[STARK Prover]:::lib
                P3Verifier[STARK Verifier]:::lib
            end
        end

        %% Internal Rust Wiring
        FnCommit --> Argon2Lib
        Argon2Lib --> PoseidonLib
        
        FnProve --> Argon2Lib
        Argon2Lib --> TraceGen
        TraceGen --> P3Prover
        AirDef -.-> P3Prover
        
        FnVerify --> P3Verifier
        AirDef -.-> P3Verifier
        PoseidonLib -.-> P3Prover & P3Verifier
    end

    %% --- DATA LAYER ---
    subgraph Backend ["☁️ Backend / Storage"]
        DB[(User Database<br/>Commitment + Salt)]:::db
    end

    %% --- DATA FLOWS ---
    UI <--> JS

    %% 1. Registration Flow
    JS -- "1. Pass (String)" --> FnCommit
    FnCommit -- "Commitment (u64)" --> JS
    JS -- "Store" --> DB

    %% 2. Proving Flow
    JS -- "2. Pass + Salt + Nonce" --> FnProve
    FnProve -- "Proof (Bytes)" --> JS

    %% 3. Verification Flow
    JS -- "3. Proof + Commitment + Nonce" --> FnVerify
    FnVerify -- "Result (bool)" --> JS
    
    %% DB Read
    DB -. "Fetch Salt/Commitment" .-> JS
```