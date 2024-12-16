import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.db.ByRecordAccessLayer
import net.daester.david.haveIBeenPwnedImporter.jooq.tables.records.HashRecord
import net.daester.david.haveIBeenPwnedImporter.jooq.tables.references.HASH
import net.daester.david.haveIBeenPwnedImporter.jooq.tables.references.HASH_PREFIX_FILE_HASH_COUNT_VIEW
import net.daester.david.haveIBeenPwnedImporter.model.Checksum
import net.daester.david.haveIBeenPwnedImporter.model.Prefix
import net.daester.david.haveIBeenPwnedImporter.model.SingleRecordHashWithOccurrence
import org.jooq.DSLContext
import org.jooq.SQLDialect
import org.jooq.impl.DSL

private data object MariaDB {
    private val logger = KotlinLogging.logger { }
    private lateinit var context: DSLContext

    fun setupContext(
        dbHostAndPortPart: String,
        dbUser: String,
        dbPassword: String,
        dbSchema: String,
    ): DSLContext {
        if (!this::context.isInitialized) {
            val config =
                HikariConfig().apply {
                    jdbcUrl = "jdbc:mariadb://$dbHostAndPortPart/$dbSchema"
                    username = dbUser
                    password = dbPassword
                    maximumPoolSize = 100
                    addDataSourceProperty("cachePrepStmts", true)
                    addDataSourceProperty("prepStmtCacheSize", 1000)
                    addDataSourceProperty("prepStmtCacheSqlLimit", 4098)
                    // addDataSourceProperty("useServerPrepStmts", true)
                    // addDataSourceProperty("useLocalSessionState", true)
                    addDataSourceProperty("rewriteBatchedStatements", true)
                    // addDataSourceProperty("cacheResultSetMetadata", true)
                    // addDataSourceProperty("cacheServerConfiguration", true)
                    // addDataSourceProperty("elideSetAutoCommits", true)
                    // addDataSourceProperty("maintainTimeStats", false)
                }
            val hikariDataSource = HikariDataSource(config)
            context = DSL.using(hikariDataSource.connection, SQLDialect.MARIADB)

            runBlocking {
                context.createTableIfNotExists(HASH).columns(HASH.fields().asList()).indexes(HASH.indexes).awaitFirst()
                context.createOrReplaceView(HASH_PREFIX_FILE_HASH_COUNT_VIEW, *HASH_PREFIX_FILE_HASH_COUNT_VIEW.fields())
            }
        }
        return context
    }
}

class MariaDbByRecordAccessLayer(
    dbHostAndPortPart: String,
    dbUser: String,
    dbPassword: String,
    dbSchema: String,
) : ByRecordAccessLayer {
    private val jooq: DSLContext = MariaDB.setupContext(dbHostAndPortPart, dbUser, dbPassword, dbSchema)
    private val logger = KotlinLogging.logger { }

    override suspend fun countByPrefixAndChecksum(
        prefix: Prefix,
        checksum: Checksum,
    ): Long =
        jooq.select(HASH_PREFIX_FILE_HASH_COUNT_VIEW.HASHES)
            .from(HASH_PREFIX_FILE_HASH_COUNT_VIEW)
            .where(HASH_PREFIX_FILE_HASH_COUNT_VIEW.HASH_PREFIX.eq(prefix))
            .and(HASH_PREFIX_FILE_HASH_COUNT_VIEW.FILE_HASH.eq(checksum))
            .awaitFirst().also { logger.trace { "Counted entries for $prefix with checksum $checksum: ${it.value1() ?: 0}" } }
            .value1() ?: 0

    override suspend fun deleteByPrefixAndNotMatchingChecksum(
        prefix: Prefix,
        checksum: Checksum,
    ): Long =
        jooq.delete(HASH).where(HASH.HASH_PREFIX.eq(prefix)).and(HASH.FILE_HASH.ne(checksum)).awaitFirst().toLong().also {
            logger.trace { "Deleted entries for $prefix with checksum not equal $checksum: $it" }
        }

    override suspend fun insertBulk(hashesWithOccurrence: List<SingleRecordHashWithOccurrence>) {
        val hashes = hashesWithOccurrence.map { it.toRecord() }.toList()
        val inserted = jooq.insertInto(HASH, *HASH.fields()).valuesOfRecords(hashes).awaitFirst()
        logger.trace { "Inserted $inserted records" }
    }

    private fun SingleRecordHashWithOccurrence.toRecord(): HashRecord =
        HashRecord(
            hashPrefix = prefix,
            hashSuffix = suffix,
            occurrence = occurrence,
            fileHash = fileChecksum,
            lastUpdate = lastUpdate,
        )
}
