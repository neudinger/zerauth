const std = @import("std");
const zone = @import("zone");

// --- Configuration ---
const N_DIM: usize = 1024;
const M_DIM: usize = 256;
const Q_MOD: i32 = 1 << 23;
const Q_MASK: i32 = Q_MOD - 1;
const ETA: i32 = 2;
const REJECTION_LIMIT: i32 = 1 << 17;

fn derive_challenge(w: []const i32, nonce: []const u8) i32 {
    // Hash the commitment (w) and nonce to generate a non-interactive challenge
    // or simulate the Verifier's random choice.
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(nonce);

    // Hash the raw bytes of the vector
    const w_bytes = std.mem.sliceAsBytes(w);
    hasher.update(w_bytes);

    var hash_out: [32]u8 = undefined;
    hasher.final(&hash_out);

    // Map hash to 0 or 1 (Bit masking)
    return @as(i32, @intCast(hash_out[0] & 1));
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    // Accessing command line arguments:
    // We use the Init structure provided by Zig 0.16 new main.
    const args = try init.minimal.args.toSlice(arena);

    for (args) |arg| {
        std.log.info("arg: {s}", .{arg});
    }

    // Stdout setup
    // Use std.Io.File directly attached to stdout file descriptor (1).
    const stdout_file = std.Io.File{ .handle = std.posix.STDOUT_FILENO };
    var stdout_buffer: [4096]u8 = undefined;

    // Create the buffered writer. Note that Io.File.Writer is a struct containing 'interface: Io.Writer'.
    var stdout_file_writer = stdout_file.writer(init.io, &stdout_buffer);

    // We must use 'interface' field to access the generic Writer methods like 'print'.
    // Also we take the address of interface because print expects *Writer.
    // Actually, calling method syntax on a field often works if the parent is mutable.
    // Let's use &stdout_file_writer.interface for clarity when needed, or just call method.
    // But since Io.Writer is a struct, we need to call print on it.

    const stdout = &stdout_file_writer.interface;

    try stdout.print("All your {s} are belong to us.\n", .{"codebase"});

    // Call helper from root.zig
    try zone.printAnotherMessage(stdout);

    try stdout.print("\n=== HIGH PERFORMANCE ZIG LATTICE ZKP ===\n", .{});
    try stdout.print("--- System Setup ---\n", .{});
    try stdout.print("Parameters: N={}, M={}, Q={}\n", .{ N_DIM, M_DIM, Q_MOD });

    // 2. Initialize Protocol Context (Generates Matrix A)
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var prover = try zone.LatticeZKP.init(allocator, init.io);
    defer prover.deinit();

    // 3. Registration Phase
    try stdout.print("\n=== 1. REGISTRATION PHASE ===\n", .{});
    const password = "UserPassword123!";
    const salt = "RandomSaltValue";

    // Prover derives Secret Key (s) and Public Key (t)
    const public_key_t = try prover.derive_secret(password, salt, init.io);
    // Note: derive_secret allocates memory for public_key_t, we must free it later
    defer allocator.free(public_key_t);

    try stdout.print(" > Derived Secret Key (s) from Password via Argon2id\n", .{});
    try stdout.print(" > Calculated Public Key (t = As)\n", .{});

    // 4. Authentication Loop
    try stdout.print("\n=== 2. AUTHENTICATION PHASE ===\n", .{});

    var attempts: usize = 0;
    var proof_accepted = false;

    // Loop until a valid proof is generated (handling Rejection Sampling)
    while (!proof_accepted) : (attempts += 1) {
        // A. COMMITMENT (Prover)
        // Prover generates random y, computes w = Ay
        const w = try prover.create_commitment();
        defer allocator.free(w);

        // B. CHALLENGE (Verifier)
        // In a real net app, 'w' is sent to Server, Server returns 'c'.P
        // Here we simulate it by hashing 'w' with a nonce.
        const challenge = derive_challenge(w, "ServerNonceMessage");

        // C. RESPONSE (Prover)
        // Prover computes z = y + c*s
        // This might return null if z is "too large" (Rejection Sampling)
        if (prover.create_response(challenge)) |z| {
            defer allocator.free(z);

            try stdout.print("[Attempt {}] Challenge: {} | Response Generated (Size N)\n", .{ attempts + 1, challenge });

            // D. VERIFICATION (Verifier)
            // Server checks if Az == w + ct
            // Note: In this demo 'prover' acts as the verifier too because it holds Matrix A.
            const is_valid = prover.verify(w, challenge, z, public_key_t);

            if (is_valid) {
                try stdout.print("\nSUCCESS: Zero Knowledge Proof Verified!\n", .{});
                try stdout.print(" > The prover knows the password without revealing it.\n", .{});
                proof_accepted = true;
            } else {
                try stdout.print("\nFAILURE: Proof Math Invalid.\n", .{});
                break; // Should not happen if math is correct
            }
        } else {
            // Rejection Sampling triggered (Security feature to prevent statistical leaks)
            try stdout.print("[Attempt {}] Response unsafe (Rejection Sampling). Retrying...\n", .{attempts + 1});
        }
    }

    // Flush the buffer at end
    try stdout_file_writer.flush();
}
