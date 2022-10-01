from app import db


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    initials = db.Column(db.String(1000))
    price = db.Column(db.DECIMAL)
    img = db.Column(db.String(1000))
    team = db.Column(db.Integer)

    def to_json(self):
        return {
            "name": self.name,
            "initials": self.initials,
            "price": self.price,
            "img": self.img,
            "team": self.team
        }


db.create_all()
