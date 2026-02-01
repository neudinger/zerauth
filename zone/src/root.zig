const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Io = std.Io;

const log = std.log.scoped(.root);

pub fn printAnotherMessage(writer: anytype) !void {
    try writer.print("Run `zig build test` to run the tests.\n", .{});
}

// --- Context Struct (The Lattice Object) ---
pub const LatticeZKP = struct {
    allocator: std.mem.Allocator,
    a_matrix: []i32, // Flattened N x M matrix
    prng: std.Random.DefaultCsprng,

    // Internal state for ZKP protocol (Prover Role)
    secret_key_s: ?[]i32 = null,
    internal_mask_y: ?[]i32 = null,

    // Constants for the scheme
    pub const dimension_secret_n: usize = 1024;
    pub const dimension_public_m: usize = 256;
    pub const modulus_q: i32 = 1 << 23;
    pub const modulus_limit: i32 = modulus_q - 1;
    // Rejection sampling bound (simplified)
    // Rejection sampling bound (simplified)
    pub const rejection_limit: i32 = 1 << 17;
    // Smallness parameter for secret key and noise
    pub const eta: i32 = 2;

    // Type aliases for clarity
    const VectorContainerTypeN = [dimension_secret_n]i32;

    // Initialize with a provided seed (Deterministic / WASM friendly)
    pub fn initWithSeed(backing_allocator: std.mem.Allocator, seed: [32]u8) !*LatticeZKP {
        const self = try backing_allocator.create(LatticeZKP);
        self.allocator = backing_allocator;
        self.secret_key_s = null;
        self.internal_mask_y = null;

        self.prng = std.Random.DefaultCsprng.init(seed);

        // Allocate Matrix A (Mock generation)
        self.a_matrix = try backing_allocator.alloc(i32, dimension_secret_n * dimension_public_m);

        // Fill Matrix A with random values mod Q
        var matrix_index: usize = 0;
        const random = self.prng.random();
        while (matrix_index < dimension_secret_n * dimension_public_m) : (matrix_index += 1) {
            self.a_matrix[matrix_index] = random.intRangeLessThan(i32, 0, modulus_q);
        }

        return self;
    }

    // Initialize with system entropy (reads /dev/urandom via POSIX, or random_get on WASI)
    pub fn init(backing_allocator: std.mem.Allocator) !*LatticeZKP {
        const builtin = @import("builtin");
        var seed: [32]u8 = undefined;

        switch (builtin.os.tag) {
            .wasi => {
                const rc = std.os.wasi.random_get(&seed, seed.len);
                if (rc != .SUCCESS) return error.SystemResources;
            },
            else => {
                // Low-level POSIX open - avoids std's Capability IO requirement
                const fd = try std.posix.openat(std.posix.AT.FDCWD, "/dev/urandom", .{}, 0);
                defer std.posix.close(fd);

                var offset: usize = 0;
                while (offset < seed.len) {
                    const n = try std.posix.read(fd, seed[offset..]);
                    if (n == 0) return error.UnexpectedEof;
                    offset += n;
                }
            },
        }

        return initWithSeed(backing_allocator, seed);
    }

    pub fn deinit(self: *LatticeZKP) void {
        if (self.secret_key_s) |s_ptr| self.allocator.free(s_ptr);
        if (self.internal_mask_y) |y_ptr| self.allocator.free(y_ptr);
        self.allocator.free(self.a_matrix);
        self.allocator.destroy(self);
    }

    /// Derive secret key 's' from password and calculate public key 't = As'
    /// Returns public key 't' (caller owns memory)
    pub fn derive_secret(self: *LatticeZKP, password: []const u8, salt: []const u8, io_context: Io) ![]i32 {
        var seed: [32]u8 = undefined;
        // Use Argon2id for password hashing / KDF
        // Parameters: t=2, m=64MB, p=1 (Matched with C++ OpenSSL implementation)
        var argon2_params = crypto.pwhash.argon2.Params.owasp_2id;
        argon2_params.t = 2; // Lower computation for demo
        argon2_params.m = 65536; // 64MB (C++ uses 65536 KB)

        try crypto.pwhash.argon2.kdf(
            self.allocator,
            &seed,
            password,
            salt,
            argon2_params,
            .argon2id,
            io_context,
        );

        // Expand seed into secret vector 's' (small coefficients for LWE)
        // We use the derived key to seed a PRNG for deterministic 's' generation from password
        var secret_prng = std.Random.DefaultCsprng.init(seed);
        const secret_random = secret_prng.random();

        // 's' must be small, e.g., ternary {-1, 0, 1} or small Gaussian (simplified here)
        const secret_key_s_local = try self.allocator.alloc(i32, dimension_secret_n);

        for (secret_key_s_local) |*coefficient| {
            // Random in [-eta, eta]
            coefficient.* = secret_random.intRangeAtMost(i32, -eta, eta);
        }

        // Store 's' in self for later ZKP steps
        if (self.secret_key_s) |old_s| self.allocator.free(old_s);
        self.secret_key_s = secret_key_s_local;

        // Calculate t = A * s mod Q
        // t is size N
        const public_key_t = try self.allocator.alloc(i32, dimension_public_m);
        // Do Matrix-Vector multiplication
        self.mul_matrix_vector(secret_key_s_local, public_key_t);

        return public_key_t;
    }

    /// Step 1: Prover generates 'y' and commitment 'w = Ay'
    /// Returns 'w' (caller owns memory).
    pub fn create_commitment(self: *LatticeZKP) ![]i32 {
        // Generate y (size M), with coeff in higher range than s
        const ephemeral_mask_y = try self.allocator.alloc(i32, dimension_secret_n);

        const random = self.prng.random();
        for (ephemeral_mask_y) |*mask_value| {
            // Range significantly larger than challenge * s range
            mask_value.* = random.intRangeAtMost(i32, -rejection_limit, rejection_limit);
        }

        // Store y
        if (self.internal_mask_y) |old_y| self.allocator.free(old_y);
        self.internal_mask_y = ephemeral_mask_y;

        // w = A * y
        const commitment_vector_w = try self.allocator.alloc(i32, dimension_public_m);
        self.mul_matrix_vector(ephemeral_mask_y, commitment_vector_w);
        return commitment_vector_w;
    }

    /// Step 2: Prover computes z = y + c*s
    /// Here c is a scalar challenge (0 or 1).
    pub fn create_response(self: *LatticeZKP, challenge_c: i32) ?[]i32 {
        if (self.secret_key_s == null or self.internal_mask_y == null) return null;

        const secret_key_s_local = self.secret_key_s.?;
        const internal_mask_y_local = self.internal_mask_y.?;

        const response_vector_z = self.allocator.alloc(i32, dimension_secret_n) catch return null;

        // z = y + c*s
        // Check norms for Rejection Sampling
        var is_valid = true;
        for (response_vector_z, 0..) |*response_val, loop_idx| {
            const val_calc = internal_mask_y_local[loop_idx] + challenge_c * secret_key_s_local[loop_idx];
            // Rejection sampling check: |z| should be < B - limit
            // Simplistic check
            if (val_calc > (rejection_limit - eta) or val_calc < (-rejection_limit + eta)) {
                is_valid = false;
            }
            response_val.* = val_calc;
        }

        if (!is_valid) {
            self.allocator.free(response_vector_z);
            return null;
        }
        return response_vector_z;
    }

    /// Verifier checks if Az = w + ct
    pub fn verify(self: *LatticeZKP, commitment_vector_w: []const i32, challenge_c: i32, response_vector_z: []const i32, public_key_t: []const i32) bool {
        // Compute Az
        // Use alignedAlloc for potential SIMD optimization in matrix mul
        const lhs_matrix_product = self.allocator.alignedAlloc(i32, mem.Alignment.of(VectorContainerTypeN), dimension_public_m) catch return false;
        defer self.allocator.free(lhs_matrix_product);

        self.mul_matrix_vector(response_vector_z, lhs_matrix_product);

        // Compute w + ct
        for (lhs_matrix_product, 0..) |element_lhs, loop_idx| {
            const rhs_value = (commitment_vector_w[loop_idx] + challenge_c * public_key_t[loop_idx]); // mod Q ideally
            const diff = @mod(element_lhs - rhs_value, modulus_q);
            if (diff != 0) return false;
        }
        return true;
    }

    // Internal Helper

    fn mul_matrix_vector(self: *LatticeZKP, input_vector: []const i32, output_vector: []i32) void {
        // Naive O(N*M)
        @memset(output_vector, 0);
        var row_index: usize = 0;
        while (row_index < dimension_public_m) : (row_index += 1) {
            var dot_product: i64 = 0;
            var col_index: usize = 0;
            while (col_index < dimension_secret_n) : (col_index += 1) {
                // A is flattened N*M. Row major
                // A[i][j] = a_matrix[i*M + j]
                const matrix_val = self.a_matrix[row_index * dimension_secret_n + col_index];
                dot_product += @as(i64, matrix_val) * input_vector[col_index];
            }
            output_vector[row_index] = @intCast(@mod(dot_product, modulus_q));
        }
    }
};
