from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()


def create_database_engine(db_url: str = "sqlite:///hdfm_sbom.db"):
    """Create SQLAlchemy engine"""
    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


def create_session(engine):
    """Create database session"""
    Session = sessionmaker(bind=engine)
    return Session()

