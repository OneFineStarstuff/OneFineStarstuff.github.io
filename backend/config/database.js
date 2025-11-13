/**
 * PostgreSQL Database Configuration with Encryption
 * Handles database connection, pooling, and encrypted data operations
 */

import { Pool } from 'pg';
import logger from '../utils/logger.js';
import { encryptField, decryptField } from '../utils/encryption.js';

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'turning_wheel',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  
  // SSL configuration for production
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false,
    ca: process.env.DB_SSL_CA,
    cert: process.env.DB_SSL_CERT,
    key: process.env.DB_SSL_KEY
  } : false,
  
  // Connection pool settings
  min: parseInt(process.env.DB_POOL_MIN || '2'),
  max: parseInt(process.env.DB_POOL_MAX || '20'),
  idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
  connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT || '2000'),
  
  // Additional options
  application_name: 'turning-wheel-api',
  statement_timeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '30000'),
  query_timeout: parseInt(process.env.DB_QUERY_TIMEOUT || '30000')
};

// Create connection pool
export const pool = new Pool(dbConfig);

// Connection pool event handlers
pool.on('connect', (client) => {
  logger.db('CONNECT', 'postgresql', 0, { 
    host: dbConfig.host,
    database: dbConfig.database 
  });
});

pool.on('error', (err, client) => {
  logger.error('PostgreSQL pool error:', err);
});

pool.on('remove', (client) => {
  logger.db('DISCONNECT', 'postgresql', 0);
});

/**
 * Initialize database connection and create necessary tables.
 *
 * This function establishes a connection to the database using the provided configuration,
 * tests the connection by executing a simple query, and logs the connection details.
 * If the connection is successful, it proceeds to create the required tables by calling
 * the createTables function. In case of any errors during the process, it logs the error
 * and rethrows it for further handling.
 */
export async function initializeDatabase() {
  try {
    logger.startup('Database', 'connecting', { host: dbConfig.host, database: dbConfig.database });
    
    // Test connection
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    
    logger.startup('Database', 'connected', { 
      timestamp: result.rows[0].now,
      poolSize: pool.totalCount
    });
    
    // Create tables if they don't exist
    await createTables();
    
    logger.startup('Database', 'initialized');
    
    return true;
  } catch (error) {
    logger.error('Database initialization failed:', error);
    throw error;
  }
}

/**
 * Create database tables and initialize the database schema.
 *
 * This function connects to the database, begins a transaction, and creates several tables including users, wheel_stages, user_progress, user_sessions, user_encrypted_data, analytics_events, and audit_logs. It also enables necessary extensions, creates indexes for performance, and sets up triggers for updating timestamps. Finally, it inserts default wheel stages if they do not already exist. If any error occurs, the transaction is rolled back.
 *
 * @returns {Promise<void>} A promise that resolves when the tables are created and initialized.
 * @throws {Error} If there is an error during the database operations.
 */
async function createTables() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Enable extensions
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";
      CREATE EXTENSION IF NOT EXISTS "citext";
    `);
    
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        username VARCHAR(50) UNIQUE NOT NULL,
        email CITEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        encryption_salt TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        is_active BOOLEAN DEFAULT true,
        email_verified BOOLEAN DEFAULT false,
        email_verification_token TEXT,
        email_verification_expires TIMESTAMPTZ,
        password_reset_token TEXT,
        password_reset_expires TIMESTAMPTZ,
        last_login TIMESTAMPTZ,
        login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMPTZ,
        avatar_url TEXT,
        bio TEXT,
        preferences JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    // Wheel stages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS wheel_stages (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        symbol TEXT NOT NULL,
        essence TEXT NOT NULL,
        meaning TEXT NOT NULL,
        action TEXT NOT NULL,
        chant TEXT NOT NULL,
        order_index INTEGER NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    // User journey progress table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_progress (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        stage_id INTEGER NOT NULL REFERENCES wheel_stages(id),
        time_spent INTEGER NOT NULL DEFAULT 0,
        insights_encrypted JSONB,
        completed_actions TEXT[],
        mood VARCHAR(20) CHECK (mood IN ('peaceful', 'contemplative', 'energized', 'emotional', 'confused', 'inspired')),
        rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        session_id UUID,
        started_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    // User sessions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_token TEXT UNIQUE NOT NULL,
        refresh_token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used TIMESTAMPTZ DEFAULT NOW(),
        ip_address INET,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT true
      );
    `);
    
    // Encrypted user data table (for sensitive information)
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_encrypted_data (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        data_type VARCHAR(50) NOT NULL,
        encrypted_data JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, data_type)
      );
    `);
    
    // Analytics events table
    await client.query(`
      CREATE TABLE IF NOT EXISTS analytics_events (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        event_type VARCHAR(50) NOT NULL,
        event_data JSONB NOT NULL,
        session_id UUID,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    // Audit log table
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        resource_type VARCHAR(50) NOT NULL,
        resource_id TEXT,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    // Create indexes for performance
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
      CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
      
      CREATE INDEX IF NOT EXISTS idx_user_progress_user_id ON user_progress(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_progress_stage_id ON user_progress(stage_id);
      CREATE INDEX IF NOT EXISTS idx_user_progress_session_id ON user_progress(session_id);
      CREATE INDEX IF NOT EXISTS idx_user_progress_created_at ON user_progress(created_at);
      
      CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
      
      CREATE INDEX IF NOT EXISTS idx_user_encrypted_data_user_id ON user_encrypted_data(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_encrypted_data_type ON user_encrypted_data(data_type);
      
      CREATE INDEX IF NOT EXISTS idx_analytics_events_user_id ON analytics_events(user_id);
      CREATE INDEX IF NOT EXISTS idx_analytics_events_type ON analytics_events(event_type);
      CREATE INDEX IF NOT EXISTS idx_analytics_events_created_at ON analytics_events(created_at);
      
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
    `);
    
    // Create triggers for updated_at columns
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
      
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
      
      DROP TRIGGER IF EXISTS update_wheel_stages_updated_at ON wheel_stages;
      CREATE TRIGGER update_wheel_stages_updated_at
        BEFORE UPDATE ON wheel_stages
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
      
      DROP TRIGGER IF EXISTS update_user_progress_updated_at ON user_progress;
      CREATE TRIGGER update_user_progress_updated_at
        BEFORE UPDATE ON user_progress
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
      
      DROP TRIGGER IF EXISTS update_user_encrypted_data_updated_at ON user_encrypted_data;
      CREATE TRIGGER update_user_encrypted_data_updated_at
        BEFORE UPDATE ON user_encrypted_data
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    `);
    
    await client.query('COMMIT');
    logger.startup('Database', 'tables created');
    
    // Insert default wheel stages if they don't exist
    await insertDefaultWheelStages();
    
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Insert default wheel stages into the database if none exist.
 *
 * This asynchronous function connects to the database and checks if any wheel stages are already present.
 * If no stages are found, it inserts a predefined set of default stages, each with attributes such as title,
 * symbol, essence, meaning, action, chant, and order_index. The function also logs the insertion process
 * and handles any potential errors during the database operations.
 */
async function insertDefaultWheelStages() {
  const defaultStages = [
    {
      title: "Creative Remembering",
      symbol: "🌱",
      essence: "The seeds of the past are unearthed, not as static relics, but as living fragments ready to be reimagined.",
      meaning: "Our histories are fertile soil — the fragments we carry forward become the foundation for new growth.",
      action: "Hold a small stone or seed and name aloud one memory you wish to carry forward.",
      chant: "In the deep hum of time, I awaken what was —\nCreative Remembering, the seeds unbroken.",
      order_index: 1
    },
    {
      title: "Stabilizing Recursion",
      symbol: "🌀",
      essence: "The rhythm of return.",
      meaning: "Patterns that repeat are not stagnation but refinement; each loop strengthens the structure of our understanding.",
      action: "Draw a spiral in the air or sand, each loop slower and more deliberate than the last.",
      chant: "Circling back, steadier with each return —\nStabilizing Recursion, the spiral ascends.",
      order_index: 2
    },
    {
      title: "Fertile Void",
      symbol: "⚫",
      essence: "Potential disguised as stillness.",
      meaning: "The empty space is never truly empty — within it, possibilities germinate, awaiting the right moment to bloom.",
      action: "Close your eyes and place your palms upward, breathing deeply into stillness.",
      chant: "I stand in the pregnant pause —\nFertile Void, where nothing hides from becoming.",
      order_index: 3
    },
    {
      title: "Emergence",
      symbol: "🌿",
      essence: "Birth from the unseen.",
      meaning: "What was incubated in silence takes visible form, a testament to the power of quiet creation.",
      action: "Slowly raise your hands from your lap to the sky as though lifting new life into the light.",
      chant: "From the silence, green light rises —\nEmergence, the shape of the unseen made flesh.",
      order_index: 4
    },
    {
      title: "New Myths and Realities",
      symbol: "📖",
      essence: "Story as architecture.",
      meaning: "Narrative is how we scaffold reality. These fresh myths set the tone for how we live, love, and create together.",
      action: "Speak aloud one sentence of a new story you want to live into.",
      chant: "We weave in firelight and shadow —\nNew Myths and Realities, the loom never still.",
      order_index: 5
    },
    {
      title: "Resonant Patterns",
      symbol: "💧",
      essence: "The echo across time.",
      meaning: "Well-told stories ripple outward, gathering new meaning with every telling, binding generations together.",
      action: "Strike a gentle rhythm (on a drum, table, or your chest) and let it carry for several beats.",
      chant: "Our stories ripple outward —\nResonant Patterns, kissing the shores of tomorrow.",
      order_index: 6
    },
    {
      title: "Adaptive Morphogenesis",
      symbol: "🦋",
      essence: "Evolution without erasure.",
      meaning: "Life reshapes itself without losing its heart; change is survival, but also artistry.",
      action: "Shift your posture or stance, moving fluidly as though becoming something new.",
      chant: "We bend, but do not break —\nAdaptive Morphogenesis, form dancing with change.",
      order_index: 7
    },
    {
      title: "The Liminal Bridge",
      symbol: "🌉",
      essence: "Connection at the threshold.",
      meaning: "Where worlds meet, ideas blend. This is where invention thrives — at the edges of difference.",
      action: "Step to the side and back, imagining one foot in each of two realms.",
      chant: "Between worlds, I walk —\nThe Liminal Bridge, my feet in two realms.",
      order_index: 8
    },
    {
      title: "Harmonic Confluence",
      symbol: "🪢",
      essence: "Difference in synchrony.",
      meaning: "Unity is not sameness; true harmony is a chorus of distinct voices finding rhythm together.",
      action: "Hum a single note, then adjust until it feels in harmony with the space around you.",
      chant: "Dissonance turns to song —\nHarmonic Confluence, each voice a thread in the chord.",
      order_index: 9
    },
    {
      title: "Archetypal Renewal",
      symbol: "🔥",
      essence: "The eternal wearing new skin.",
      meaning: "Ancient wisdom is not static — it reappears in fresh forms, guiding us into each new turning of the wheel.",
      action: "Light a candle (or imagine it vividly) and whisper the name of an ancient wisdom you wish to carry forward.",
      chant: "The ancient wears a new mask —\nArchetypal Renewal, the wheel turns once more.",
      order_index: 10
    }
  ];

  const client = await pool.connect();
  
  try {
    // Check if stages already exist
    const result = await client.query('SELECT COUNT(*) FROM wheel_stages');
    const count = parseInt(result.rows[0].count);
    
    if (count === 0) {
      logger.startup('Database', 'inserting default wheel stages');
      
      for (const stage of defaultStages) {
        await client.query(`
          INSERT INTO wheel_stages (title, symbol, essence, meaning, action, chant, order_index)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [stage.title, stage.symbol, stage.essence, stage.meaning, stage.action, stage.chant, stage.order_index]);
      }
      
      logger.startup('Database', `inserted ${defaultStages.length} wheel stages`);
    }
  } catch (error) {
    logger.error('Failed to insert default wheel stages:', error);
  } finally {
    client.release();
  }
}

/**
 * Execute a database query with error handling and logging.
 *
 * This function connects to the database, executes the provided SQL query with optional parameters,
 * and logs the duration and result of the query. In case of an error, it logs the error message and
 * rethrows the error. The database client is released after the operation, ensuring proper resource management.
 *
 * @param {string} text - The SQL query to be executed.
 * @param {Array} [params=[]] - The parameters for the SQL query.
 */
export async function query(text, params = []) {
  const start = Date.now();
  const client = await pool.connect();
  
  try {
    const result = await client.query(text, params);
    const duration = Date.now() - start;
    
    logger.db('QUERY', 'postgresql', duration, {
      query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
      rows: result.rowCount
    });
    
    return result;
  } catch (error) {
    const duration = Date.now() - start;
    logger.db('QUERY_ERROR', 'postgresql', duration, {
      query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
      error: error.message
    });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Execute a transaction.
 *
 * This function establishes a connection to the database, begins a transaction,
 * and executes the provided callback function with the database client. If the
 * callback completes successfully, the transaction is committed; if an error
 * occurs, the transaction is rolled back. Finally, the database client is released.
 *
 * @param {Function} callback - A function that takes the database client as an argument
 * and performs operations within the transaction.
 */
export async function transaction(callback) {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Store encrypted data for a user in the database.
 */
export async function storeEncryptedData(userId, dataType, data) {
  const encryptedData = encryptField(data);
  
  await query(`
    INSERT INTO user_encrypted_data (user_id, data_type, encrypted_data)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, data_type)
    DO UPDATE SET encrypted_data = $3, updated_at = NOW()
  `, [userId, dataType, JSON.stringify(encryptedData)]);
}

/**
 * Retrieve and decrypt encrypted data for a user.
 */
export async function getEncryptedData(userId, dataType) {
  const result = await query(`
    SELECT encrypted_data FROM user_encrypted_data
    WHERE user_id = $1 AND data_type = $2
  `, [userId, dataType]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  const encryptedData = result.rows[0].encrypted_data;
  return decryptField(encryptedData);
}

/**
 * Closes the database connection.
 */
export async function closeDatabase() {
  try {
    await pool.end();
    logger.shutdown('Database', 'connection closed');
  } catch (error) {
    logger.error('Error closing database:', error);
  }
}

/**
 * Performs a health check on the database.
 *
 * This function executes a simple query to verify the database's availability.
 * It checks if the result indicates a healthy state by comparing the returned value
 * to 1. In case of an error during the query execution, it logs the error and
 * returns false to indicate an unhealthy state.
 */
export async function healthCheck() {
  try {
    const result = await query('SELECT 1 as healthy');
    return result.rows[0].healthy === 1;
  } catch (error) {
    logger.error('Database health check failed:', error);
    return false;
  }
}

export default {
  pool,
  query,
  transaction,
  initializeDatabase,
  closeDatabase,
  healthCheck,
  storeEncryptedData,
  getEncryptedData
};
