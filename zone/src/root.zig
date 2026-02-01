const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Io = std.Io;

pub fn printAnotherMessage(writer: anytype) !void {
    try writer.print("Run `zig build test` to run the tests.\n", .{});
}

// --- Context Struct (The Lattice Object) ---
pub const LatticeZKP = struct {
    allocator: std.mem.Allocator,
    a_matrix: []i32, // Flattened N x M matrix
    prng: std.Random.DefaultCsprng,

    // Internal state for ZKP protocol (Prover Role)
    secret_s: ?[]i32 = null,
    current_y: ?[]i32 = null,

    // Constants for the scheme
    pub const N: usize = 1024;
    pub const M: usize = 256;
    pub const Q: i32 = 1 << 23;
    pub const Q_LIMIT: i32 = Q - 1;
    // Rejection sampling bound (simplified)
    pub const B: i32 = 1 << 14;

    // Type aliases for clarity
    const Vec = [N]i32;

    pub fn init(backing_allocator: std.mem.Allocator, io: Io) !*LatticeZKP {
        const self = try backing_allocator.create(LatticeZKP);
        self.allocator = backing_allocator;
        self.secret_s = null;
        self.current_y = null;

        // Initialize CSPRNG with system entropy (read /dev/urandom)
        var seed: [32]u8 = undefined;
        {
            var f = try Io.Dir.openFileAbsolute(io, "/dev/urandom", .{});
            defer f.close(io);

            // Read seed using readStreaming loop
            var off: usize = 0;
            while (off < seed.len) {
                var iov = [_][]u8{seed[off..]};
                const n = try f.readStreaming(io, &iov);
                if (n == 0) return error.UnexpectedEof;
                off += n;
            }
        }
        self.prng = std.Random.DefaultCsprng.init(seed);

        // Allocate Matrix A (Mock generation)
        self.a_matrix = try backing_allocator.alloc(i32, N * M);

        // Fill Matrix A with random values mod Q
        var i: usize = 0;
        const random = self.prng.random();
        while (i < N * M) : (i += 1) {
            self.a_matrix[i] = random.intRangeLessThan(i32, 0, Q);
        }

        return self;
    }

    pub fn deinit(self: *LatticeZKP) void {
        if (self.secret_s) |s| self.allocator.free(s);
        if (self.current_y) |y| self.allocator.free(y);
        self.allocator.free(self.a_matrix);
        self.allocator.destroy(self);
    }

    /// Derive secret key 's' from password and calculate public key 't = As'
    /// Returns public key 't' (caller owns memory)
    pub fn derive_secret(self: *LatticeZKP, password: []const u8, salt: []const u8, io: Io) ![]i32 {
        var seed: [32]u8 = undefined;
        // Use Argon2id for password hashing / KDF
        // Parameters: t=2, m=19MB, p=1 (OWASP recommendations, scaled down for demo speed)
        var params = crypto.pwhash.argon2.Params.owasp_2id;
        params.t = 2; // Lower computation for demo
        params.m = 1024; // Lower memory for demo

        try crypto.pwhash.argon2.kdf(
            self.allocator,
            &seed,
            password,
            salt,
            params,
            .argon2id,
            io,
        );

        // Expand seed into secret vector 's' (small coefficients for LWE)
        // We use the derived key to seed a PRNG for deterministic 's' generation from password
        var secret_prng = std.Random.DefaultCsprng.init(seed);
        const secret_random = secret_prng.random();

        // 's' must be small, e.g., ternary {-1, 0, 1} or small Gaussian (simplified here)
        const s = try self.allocator.alloc(i32, M);

        for (s) |*coeff| {
            // Random in [-2, 2]
            coeff.* = secret_random.intRangeAtMost(i32, -2, 2);
        }

        // Store 's' in self for later ZKP steps
        if (self.secret_s) |old_s| self.allocator.free(old_s);
        self.secret_s = s;

        // Calculate t = A * s mod Q
        // t is size N
        const t = try self.allocator.alloc(i32, N);
        // Do Matrix-Vector multiplication
        self.mul_matrix_vector(s, t);

        return t;
    }

    /// Step 1: Prover generates 'y' and commitment 'w = Ay'
    /// Returns 'w' (caller owns memory).
    pub fn create_commitment(self: *LatticeZKP) ![]i32 {
        // Generate y (size M), with coeff in higher range than s
        const y = try self.allocator.alloc(i32, M);

        const random = self.prng.random();
        for (y) |*val| {
            // Range significantly larger than challenge * s range
            val.* = random.intRangeLessThan(i32, -B, B);
        }

        // Store y
        if (self.current_y) |old_y| self.allocator.free(old_y);
        self.current_y = y;

        // w = A * y
        const w = try self.allocator.alloc(i32, N);
        self.mul_matrix_vector(y, w);
        return w;
    }

    /// Step 2: Prover computes z = y + c*s
    /// Here c is a scalar challenge (0 or 1).
    pub fn create_response(self: *LatticeZKP, challenge: i32) ?[]i32 {
        if (self.secret_s == null or self.current_y == null) return null;

        const s = self.secret_s.?;
        const y = self.current_y.?;

        const z = self.allocator.alloc(i32, M) catch return null;

        // z = y + c*s
        // Check norms for Rejection Sampling
        var valid = true;
        for (z, 0..) |*val, i| {
            const val_calc = y[i] + challenge * s[i];
            // Rejection sampling check: |z| should be < B - limit
            // Simplistic check
            if (val_calc > (B - 100) or val_calc < (-B + 100)) {
                valid = false;
            }
            val.* = val_calc;
        }

        if (!valid) {
            self.allocator.free(z);
            return null;
        }
        return z;
    }

    /// Verifier checks if Az = w + ct
    pub fn verify(self: *LatticeZKP, w: []const i32, c: i32, z: []const i32, t: []const i32) bool {
        // Compute Az
        // Use alignedAlloc for potential SIMD optimization in matrix mul
        const az = self.allocator.alignedAlloc(i32, mem.Alignment.of(Vec), N) catch return false;
        defer self.allocator.free(az);

        self.mul_matrix_vector(z, az);

        // Compute w + ct
        for (az, 0..) |elem, i| {
            const rhs = (w[i] + c * t[i]); // mod Q ideally
            const diff = @mod(elem - rhs, Q);
            if (diff != 0) return false;
        }
        return true;
    }

    // Internal Helper
    fn mul_matrix_vector(self: *LatticeZKP, vec_in: []const i32, vec_out: []i32) void {
        // Naive O(N*M)
        @memset(vec_out, 0);
        var i: usize = 0;
        while (i < N) : (i += 1) {
            var dot: i64 = 0;
            var j: usize = 0;
            while (j < M) : (j += 1) {
                // A is flattened N*M. Row major
                // A[i][j] = a_matrix[i*M + j]
                const val = self.a_matrix[i * M + j];
                dot += @as(i64, val) * vec_in[j];
            }
            vec_out[i] = @intCast(@mod(dot, Q));
        }
    }
};
