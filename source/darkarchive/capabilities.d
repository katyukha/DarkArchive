/// Archive capability declarations.
///
/// Types (readers, writers) declare which capabilities they support via a
/// static `supports` method:
///
///   static bool supports(ArchiveCapability cap);
///
/// The high-level API uses this at compile time for dispatch and at runtime
/// for user-facing format queries (`darkarchive.archive.supports`).
///
/// The set of capabilities is expected to grow as new formats and access
/// patterns are added (e.g. seekable reads, random-access writes).
module darkarchive.capabilities;

/// Capability that an archive reader or writer may declare support for.
enum ArchiveCapability {
    streamingRead,    /// Sequential streaming read   (TAR, TAR.GZ readers)
    streamingWrite,   /// Sequential streaming write  (TAR, TAR.GZ writers)
    randomAccessRead, /// Random-access entry reads by index  (ZIP reader)
    randomAccessWrite,/// Random-access entry writes / central directory (ZIP writer)
    hardlinks,        /// Native hardlink entries (TAR typeflag '1'; ZIP has no equivalent)
}
