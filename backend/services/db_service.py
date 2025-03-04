import psycopg2
import logging
from contextlib import contextmanager
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseConnection:
    def __init__(self, host='localhost', port=5432, dbname='mydb', 
                 user='postgres', password='password'):
        self.connection_params = {
            'host': host,
            'port': port,
            'dbname': dbname,
            'user': user,
            'password': password
        }
        self.connection = None
        logger.info(f"Database connection initialized for {dbname}")

    def connect(self):
        """Establish a direct database connection"""
        try:
            self.connection = psycopg2.connect(**self.connection_params)
            logger.info("Database connection established successfully")
            return self.connection
        except psycopg2.Error as e:
            logger.error(f"Error connecting to the database: {e}")
            raise

    def close(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("Database connection closed")

    @contextmanager
    def get_cursor(self, commit=False):
        """Context manager for database cursor"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            if commit:
                self.connection.commit()
                logger.info("Transaction committed")
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Transaction rolled back due to error: {e}")
            raise
        finally:
            cursor.close()

    def execute_query(self, query, params=None, fetch=True, commit=True):
        """Execute a database query and return results"""
        try:
            with self.get_cursor(commit=commit) as cursor:
                cursor.execute(query, params or {})
                if fetch:
                    results = cursor.fetchall()
                    logger.info(f"Query executed successfully, returned {len(results)} rows")
                    return results
                return None
        except psycopg2.Error as e:
            logger.error(f"Database query error: {e}")
            raise

# Create a singleton database connection
db = DatabaseConnection()

# Compatibility function for existing code
def execute_query(query, params=None, fetch=True, commit=True):
    """
    Compatibility wrapper for the singleton database connection
    Maintains the same interface as the previous implementation
    """
    return db.execute_query(query, params, fetch, commit)