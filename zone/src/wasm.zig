const std = @import("std");
const zone = @import("zone"); // Import the module

// We need an allocator for the WASM environment
// Using SimpleAllocator or GeneralPurposeAllocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// Exported Context Pointer
const ZKPContext = *zone.LatticeZKP;

// Dummy IO for Argon2 (WASM is single threaded, so this is unused by Argon2 inner logic)
// We provide a minimal VTable to satisfy the type checker / runtime safety checks if touched.
const Io = std.Io;
const dummy_vtable = Io.VTable{
    .async = undefined,
    .concurrent = undefined,
    .await = undefined,
    .cancel = undefined,
    .groupAsync = undefined,
    .groupConcurrent = undefined,
    .groupAwait = undefined,
    .groupCancel = undefined,
    .recancel = undefined,
    .swapCancelProtection = undefined,
    .checkCancel = undefined,
    .select = undefined,
    .futexWait = undefined,
    .futexWaitUncancelable = undefined,
    .futexWake = undefined,
    .dirCreateDir = undefined,
    .dirCreateDirPath = undefined,
    .dirCreateDirPathOpen = undefined,
    .dirOpenDir = undefined,
    .dirStat = undefined,
    .dirStatFile = undefined,
    .dirAccess = undefined,
    .dirCreateFile = undefined,
    .dirCreateFileAtomic = undefined,
    .dirOpenFile = undefined,
    .dirClose = undefined,
    .dirRead = undefined,
    .dirRealPath = undefined,
    .dirRealPathFile = undefined,
    .dirDeleteFile = undefined,
    .dirDeleteDir = undefined,
    .dirRename = undefined,
    .dirRenamePreserve = undefined,
    .dirSymLink = undefined,
    .dirReadLink = undefined,
    .dirSetOwner = undefined,
    .dirSetFileOwner = undefined,
    .dirSetPermissions = undefined,
    .dirSetFilePermissions = undefined,
    .dirSetTimestamps = undefined,
    .dirHardLink = undefined,
    .fileStat = undefined,
    .fileLength = undefined,
    .fileClose = undefined,
    .fileWriteStreaming = undefined,
    .fileWritePositional = undefined,
    .fileWriteFileStreaming = undefined,
    .fileWriteFilePositional = undefined,
    .fileReadStreaming = undefined,
    .fileReadPositional = undefined,
    .fileSeekBy = undefined,
    .fileSeekTo = undefined,
    .fileSync = undefined,
    .fileIsTty = undefined,
    .fileEnableAnsiEscapeCodes = undefined,
    .fileSupportsAnsiEscapeCodes = undefined,
    .fileSetLength = undefined,
    .fileSetOwner = undefined,
    .fileSetPermissions = undefined,
    .fileSetTimestamps = undefined,
    .fileLock = undefined,
    .fileTryLock = undefined,
    .fileUnlock = undefined,
    .fileDowngradeLock = undefined,
    .fileRealPath = undefined,
    .fileHardLink = undefined,
    .fileMemoryMapCreate = undefined,
    .fileMemoryMapDestroy = undefined,
    .fileMemoryMapSetLength = undefined,
    .fileMemoryMapRead = undefined,
    .fileMemoryMapWrite = undefined,
    .processExecutableOpen = undefined,
    .processExecutablePath = undefined,
    .lockStderr = undefined,
    .tryLockStderr = undefined,
    .unlockStderr = undefined,
    .processCurrentPath = undefined,
    .processSetCurrentDir = undefined,
    .processReplace = undefined,
    .processReplacePath = undefined,
    .processSpawn = undefined,
    .processSpawnPath = undefined,
    .childWait = undefined,
    .childKill = undefined,
    .progressParentFile = undefined,
    .now = undefined,
    .sleep = undefined,
    .random = undefined,
    .randomSecure = undefined,
    .netListenIp = undefined,
    .netAccept = undefined,
    .netBindIp = undefined,
    .netConnectIp = undefined,
    .netListenUnix = undefined,
    .netConnectUnix = undefined,
    .netSend = undefined,
    .netReceive = undefined,
    .netRead = undefined,
    .netWrite = undefined,
    .netWriteFile = undefined,
    .netClose = undefined,
    .netShutdown = undefined,
    .netInterfaceNameResolve = undefined,
    .netInterfaceName = undefined,
    .netLookup = undefined,
};

const dummy_io = Io{
    .userdata = null,
    .vtable = &dummy_vtable,
};

// --- Helper for JS to allocate memory ---
export fn alloc(len: usize) ?[*]u8 {
    const buf = allocator.alloc(u8, len) catch return null;
    return buf.ptr;
}

export fn free(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}

// --- ZKP Interface ---

export fn zkp_init() ?*anyopaque {
    const instance = zone.LatticeZKP.init(allocator) catch return null;
    return instance;
}

export fn zkp_deinit(ctx: *anyopaque) void {
    const self = @as(ZKPContext, @ptrCast(@alignCast(ctx)));
    self.deinit();
}

// Returns pointer to Public Key (size M * 4 bytes). Caller must free.
// Returns null on error.
export fn zkp_derive_secret(ctx: *anyopaque, pwd_ptr: [*]const u8, pwd_len: usize, salt_ptr: [*]const u8, salt_len: usize) ?[*]const i32 {
    const self = @as(ZKPContext, @ptrCast(@alignCast(ctx)));
    const password = pwd_ptr[0..pwd_len];
    const salt = salt_ptr[0..salt_len];

    // We pass our dummy_io here. It will be unused by sync implementation of Argon2.
    const pk = self.derive_secret(password, salt, dummy_io) catch return null;

    // Convert slice to pointer for JS. JS manages strict length, but we should probably tell JS execution failed or not.
    // Memory ownership: 'pk' is allocated by allocator.
    // We return the ptr. JS should call 'free_i32_array' later?
    // Actually our 'free' takes u8. Let's provide a generic free or specific one.
    return pk.ptr;
}

// Helper to free int32 arrays created by ZKP
export fn free_i32(ptr: [*]i32, len: usize) void {
    allocator.free(ptr[0..len]);
}

export fn zkp_create_commitment(ctx: *anyopaque) ?[*]const i32 {
    const self = @as(ZKPContext, @ptrCast(@alignCast(ctx)));
    const w = self.create_commitment() catch return null;
    return w.ptr;
}

// Returns null if rejection sampling failed
export fn zkp_create_response(ctx: *anyopaque, challenge: i32) ?[*]const i32 {
    const self = @as(ZKPContext, @ptrCast(@alignCast(ctx)));
    if (self.create_response(challenge)) |z| {
        return z.ptr;
    }
    return null;
}

export fn zkp_verify(ctx: *anyopaque, w_ptr: [*]const i32, challenge: i32, z_ptr: [*]const i32, pk_ptr: [*]const i32) bool {
    const self = @as(ZKPContext, @ptrCast(@alignCast(ctx)));
    // We need strict sizes.
    // w: M, z: N, pk: M
    const w = w_ptr[0..zone.LatticeZKP.dimension_public_m];
    const z = z_ptr[0..zone.LatticeZKP.dimension_secret_n];
    const pk = pk_ptr[0..zone.LatticeZKP.dimension_public_m];

    return self.verify(w, challenge, z, pk);
}

// Getters for dimensions
export fn zkp_get_n() usize {
    return zone.LatticeZKP.dimension_secret_n;
}
export fn zkp_get_m() usize {
    return zone.LatticeZKP.dimension_public_m;
}
