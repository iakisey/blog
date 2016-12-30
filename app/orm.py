from bcrypt import hashpw, gensalt
from datetime import datetime
from sqlalchemy import (
    Column, Integer, TIMESTAMP, String, ForeignKey)

from . import Base, DBSession, p


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    hashed_password = Column(String(512), nullable=False)

    def __repr__(self):
        return 'id={} email={} name={} hashed_password={}'.format(
            self.id, self.email, self.name, self.hashed_password)

    @staticmethod
    def hash_pd(password, salt=gensalt()):
        return hashpw(password.encode(), salt)

    def verify_user(self, email, password):
        user = self.get_by_constraint({'email': email})
        if not user or not user.hashed_password.encode() == hashpw(
          password.encode(), user.hashed_password.encode()):
            return False
        return user

    # 约束筛选
    @classmethod
    def filter_by_constraint(cls, infos, constraint={}):
        infos = infos.filter(cls.id == constraint['id']) \
            if constraint.get('id') else infos
        infos = infos.filter(cls.email == constraint['email']) \
            if constraint.get('email') else infos
        infos = infos.filter(cls.name == constraint['name']) \
            if constraint.get('name') else infos
        infos = infos.filter(cls.hashed_password ==
                             constraint['hashed_password']) \
            if constraint.get('hashed_password') else infos
        return infos

    # 约束排序
    @classmethod
    def order_by_constraint(cls, infos, constraint={}):
        if 'id' in constraint:
            infos = infos.order_by(cls.id.desc()) if isinstance(
                constraint, dict) and constraint['id'] == 'desc' \
                    else infos.order_by(cls.id)
        if 'email' in constraint:
            infos = infos.order_by(cls.email.desc()) if isinstance(
                constraint, dict) and constraint['email'] == 'desc' \
                    else infos.order_by(cls.email)
        if 'name' in constraint:
            infos = infos.order_by(cls.name.desc()) if isinstance(
                constraint, dict) and constraint['name'] == 'desc' \
                    else infos.order_by(cls.name)
        return infos

    # -----增
    @classmethod
    def add(cls, info):
        session = DBSession()
        session.add(cls(
            email=info.get('email'),
            name=info.get('name'),
            hashed_password=info.get('hashed_password').decode()))
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----删
    @classmethod
    def delete(cls, constraint):
        session = DBSession()
        infos = cls.filter_by_constraint(session.query(cls), constraint)
        infos.delete()
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----改
    @classmethod
    def update(cls, data):
        session = DBSession()
        if 'id' in data:
            key = 'id'
            info = session.query(cls).filter(cls.id == data[key][key])
        if 'email' in data:
            key = 'email'
            info = session.query(cls).filter(cls.username == data[key][key])
        if 'name' in data:
            key = 'name'
            info = session.query(cls).filter(cls.username == data[key][key])
        info.update({cls.id: data[key]['id']}) if data[key].get('id') else None
        info.update({cls.username: data[key]['email']}) \
            if data[key].get('email') else None
        info.update({cls.username: data[key]['name']}) \
            if data[key].get('name') else None
        info.update({cls.password_hash: data[key]['hashed_password']}) \
            if data[key].get('hashed_password') else None
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----查
    @classmethod
    def get_by_constraint(cls, constraint={}, order={}, limit=1):
        session = DBSession()
        infos = cls.filter_by_constraint(session.query(cls), constraint)
        order = constraint if not order else order
        infos = cls.order_by_constraint(infos, order)
        infos = infos.all()
        session.close()
        return (infos[0] if limit == 1 else infos[:limit]) if infos else None


class Entries(Base):
    __tablename__ = 'entries'
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    user_id = Column(
        Integer, ForeignKey('user.id'), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    title = Column(String(512), nullable=False)
    markdown = Column(String(512), nullable=False)
    html = Column(String(512), nullable=False)
    published = Column(TIMESTAMP, index=True, nullable=False)
    updated = Column(TIMESTAMP, nullable=False)

    # 约束筛选
    @classmethod
    def filter_by_constraint(cls, infos, constraint):
        infos = infos.filter(cls.id == constraint['id']) \
            if constraint.get('id') else infos
        infos = infos.filter(cls.user_id == constraint['user_id']) \
            if constraint.get('user_id') else infos
        infos = infos.filter(cls.slug == constraint['slug']) \
            if constraint.get('slug') else infos
        infos = infos.filter(cls.title == constraint['title']) \
            if constraint.get('title') else infos
        infos = infos.filter(cls.markdown == constraint['markdown']) \
            if constraint.get('markdown') else infos
        infos = infos.filter(cls.html == constraint['html']) \
            if constraint.get('html') else infos
        infos = infos.filter(cls.published == constraint['published']) \
            if constraint.get('published') else infos
        infos = infos.filter(cls.updated == constraint['updated']) \
            if constraint.get('updated') else infos
        return infos

    # 约束排序
    @classmethod
    def order_by_constraint(cls, infos, constraint):
        if 'id' in constraint:
            infos = infos.order_by(cls.id.desc()) if isinstance(
                constraint, dict) and constraint['id'] == 'desc' \
                    else infos.order_by(cls.id)
        if 'user_id' in constraint:
            infos = infos.order_by(cls.user_id.desc()) if isinstance(
                constraint, dict) and constraint['user_id'] == 'desc' \
                    else infos.order_by(cls.user_id)
        if 'slug' in constraint:
            infos = infos.order_by(cls.slug.desc()) if isinstance(
                constraint, dict) and constraint['slug'] == 'desc' \
                    else infos.order_by(cls.slug)
        if 'title' in constraint:
            infos = infos.order_by(cls.title.desc()) if isinstance(
                constraint, dict) and constraint['title'] == 'desc' \
                    else infos.order_by(cls.title)
        if 'markdown' in constraint:
            infos = infos.order_by(cls.markdown.desc()) if isinstance(
                constraint, dict) and constraint['markdown'] == 'desc' \
                    else infos.order_by(cls.markdown)
        if 'html' in constraint:
            infos = infos.order_by(cls.html.desc()) if isinstance(
                constraint, dict) and constraint['html'] == 'desc' \
                    else infos.order_by(cls.html)
        if 'published' in constraint:
            infos = infos.order_by(cls.published.desc()) \
                if isinstance(constraint, dict) and \
                constraint['published'] == 'desc' \
                else infos.order_by(cls.published)
        if 'updated' in constraint:
            infos = infos.order_by(cls.updated.desc()) if isinstance(
                constraint, dict) and constraint['updated'] == 'desc' \
                    else infos.order_by(cls.updated)
        return infos

    # -----增
    @classmethod
    def add(cls, info):
        now = datetime.now()
        session = DBSession()
        session.add(cls(
            user_id=info.get('user_id'),
            slug=info.get('slug'),
            title=str(info.get('title')),
            markdown=info.get('markdown'),
            html=info.get('html'),
            published=now,
            updated=now))
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----删
    @classmethod
    def delete(cls, constraint):
        session = DBSession()
        infos = cls.filter_by_constraint(session.query(cls), constraint)
        infos.delete()
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----改
    @classmethod
    def update(cls, data):
        session = DBSession()
        if 'id' in data:
            key = 'id'
            info = session.query(cls).filter(cls.id == data[key][key])
        info.update({cls.id: data[key]['id']}) if data[key].get('id') else None
        info.update({cls.title: data[key]['title']}) \
            if data[key]['title'] else None
        info.update({cls.markdown: data[key]['markdown']}) \
            if data[key]['markdown'] else None
        info.update({cls.html: data[key]['html']}) \
            if data[key]['html'] else None
        info.update({cls.updated: datetime.now()})
        try:
            session.commit()
        except Exception as e:
            p.error()
            session.rollback()
            return False
        session.close()
        return True

    # -----查
    @classmethod
    def get_by_constraint(cls, constraint={}, order={}, limit=1):
        session = DBSession()
        infos = cls.filter_by_constraint(session.query(cls), constraint)
        order = constraint if not order else order
        infos = cls.order_by_constraint(infos, order)
        infos = infos.all()
        session.close()
        return (infos[0] if limit == 1 else infos[:limit]) if infos else None
