const std = @import("std");
const zone = @import("zone");

fn derive_challenge(commitment_vector: []const i32, nonce_bytes: []const u8) i32 {
    // Hash the commitment (w) and nonce to generate a non-interactive challenge
    // or simulate the Verifier's random choice.
    var blake3_hasher = std.crypto.hash.Blake3.init(.{});
    blake3_hasher.update(nonce_bytes);

    // Hash the raw bytes of the vector
    const commitment_bytes = std.mem.sliceAsBytes(commitment_vector);
    blake3_hasher.update(commitment_bytes);

    var hash_output: [32]u8 = undefined;
    blake3_hasher.final(&hash_output);

    // Map hash to 0 or 1 (Bit masking)
    return @as(i32, @intCast(hash_output[0] & 1));
}

pub fn main(process_init: std.process.Init) !void {
    const arena_allocator = process_init.arena.allocator();

    // Accessing command line arguments:
    // We use the Init structure provided by Zig 0.16 new main.
    const command_line_args = try process_init.minimal.args.toSlice(arena_allocator);

    for (command_line_args) |argument| {
        std.log.info("arg: {s}", .{argument});
    }

    // Stdout setup
    // Use std.Io.File directly attached to stdout file descriptor (1).
    const stdout_file = std.Io.File{ .handle = std.posix.STDOUT_FILENO };
    var stdout_buffer: [4096]u8 = undefined;

    // Create the buffered writer. Note that Io.File.Writer is a struct containing 'interface: Io.Writer'.
    var stdout_file_writer = stdout_file.writer(process_init.io, &stdout_buffer);

    // We must use 'interface' field to access the generic Writer methods like 'print'.
    // Also we take the address of interface because print expects *Writer.
    // Actually, calling method syntax on a field often works if the parent is mutable.
    // Let's use &stdout_file_writer.interface for clarity when needed, or just call method.
    // But since Io.Writer is a struct, we need to call print on it.

    const standard_output = &stdout_file_writer.interface;

    try standard_output.print("All your {s} are belong to us.\n", .{"codebase"});

    // Call helper from root.zig
    try zone.printAnotherMessage(standard_output);

    try standard_output.print("\n=== HIGH PERFORMANCE ZIG LATTICE ZKP ===\n", .{});
    try standard_output.print("--- System Setup ---\n", .{});
    try standard_output.print("Parameters: N={}, M={}, Q={}\n", .{ zone.LatticeZKP.dimension_secret_n, zone.LatticeZKP.dimension_public_m, zone.LatticeZKP.modulus_q });

    // 2. Initialize Protocol Context (Generates Matrix A)
    // var seed: [32]u8 = undefined;
    // try process_init.io.randomSecure(&seed);
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    const allocator = general_purpose_allocator.allocator();

    // Prover Setup
    // Initialize ZKP Prover (Generates Matrix A from random seed)
    var prover = try zone.LatticeZKP.init(allocator); // Automatically seeds from /dev/urandom

    defer prover.deinit();

    // 3. Registration Phase
    try standard_output.print("\n=== 1. REGISTRATION PHASE ===\n", .{});
    const password = "password";
    const salt_string = "saltsalt";

    // Prover derives Secret Key (s) and Public Key (t)
    const public_key_t = try prover.derive_secret(password, salt_string, process_init.io);
    // Note: derive_secret allocates memory for public_key_t, we must free it later
    defer allocator.free(public_key_t);

    try standard_output.print(" > Derived Secret Key (s) from Password via Argon2id\n", .{});
    try standard_output.print(" > Calculated Public Key (t = As)\n", .{});

    // 4. Authentication Loop
    try standard_output.print("\n=== 2. AUTHENTICATION PHASE ===\n", .{});

    var attempts_count: usize = 0;
    var proof_accepted = false;

    // Loop until a valid proof is generated (handling Rejection Sampling)
    while (!proof_accepted) : (attempts_count += 1) {
        // A. COMMITMENT (Prover)
        // Prover generates random y, computes w = Ay
        const commitment_vector = try prover.create_commitment();
        defer allocator.free(commitment_vector);

        // B. CHALLENGE (Verifier)
        // In a real net app, 'w' is sent to Server, Server returns 'c'.P
        // Here we simulate it by hashing 'w' with a nonce.
        const challenge_val = derive_challenge(commitment_vector, "ServerNonceMessage");

        // C. RESPONSE (Prover)
        // Prover computes z = y + c*s
        // This might return null if z is "too large" (Rejection Sampling)
        if (prover.create_response(challenge_val)) |response_vector| {
            defer allocator.free(response_vector);

            try standard_output.print("[Attempt {}] Challenge: {} | Response Generated (Size N)\n", .{ attempts_count + 1, challenge_val });

            // D. VERIFICATION (Verifier)
            // Server checks if Az == w + ct
            // Note: In this demo 'prover' acts as the verifier too because it holds Matrix A.
            const is_valid = prover.verify(commitment_vector, challenge_val, response_vector, public_key_t);

            if (is_valid) {
                try standard_output.print("\nSUCCESS: Zero Knowledge Proof Verified!\n", .{});
                try standard_output.print(" > The prover knows the password without revealing it.\n", .{});
                proof_accepted = true;
            } else {
                try standard_output.print("\nFAILURE: Proof Math Invalid.\n", .{});
                break; // Should not happen if math is correct
            }
        } else {
            // Rejection Sampling triggered (Security feature to prevent statistical leaks)
            try standard_output.print("[Attempt {}] Response unsafe (Rejection Sampling). Retrying...\n", .{attempts_count + 1});
        }
    }

    // Flush the buffer at end
    try stdout_file_writer.flush();
}
