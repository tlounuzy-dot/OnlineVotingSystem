"""Project package configuration."""

# PyMySQL provides Django's MySQLdb-compatible driver after requirements are installed.
try:
    import pymysql
except ImportError:
    pass
else:
    pymysql.install_as_MySQLdb()
