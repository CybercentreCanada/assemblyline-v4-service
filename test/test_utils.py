from assemblyline_v4_service.common.utils import extract_passwords


def test_extract_passwords():
    # Make sure an empty string doesn't cause any problem
    text = ""
    res = extract_passwords(text)

    # Make sure an empty string doesn't cause any problem
    text = "\n"
    res = extract_passwords(text)

    text = "Invoice Password: A"
    wanted_password = ["A"]
    res = extract_passwords(text)
    assert all([password in res for password in wanted_password])

    text = "Invoice Password: ABCDE"
    wanted_password = ["ABCDE"]
    res = extract_passwords(text)
    assert all([password in res for password in wanted_password])

    text = (
        "Password : A\nTest string \nPassword: B\nTest string\npassword:C\nTest string\npassword: D\n"
        "Test string\npassword: E \nTest string\nPassword: dhfkIJK891\nTest string\nPassword: dh_!l-k&*%#@!91\n"
        "Test string\nThe Password is: F\nTest string\nPassword:\nG\nTest string\nMot de passe: H\n"
        "Test string\nPassword:\ndhfkIJK892\nTest string\nPassword:\nKahj#@!!45\n"
    )
    wanted_password = [
        "A",
        "B",
        "C",
        "D",
        "E",
        "dhfkIJK891",
        "dh_!l-k&*%#@!91",
        "F",
        "G",
        "H",
        "dhfkIJK892",
        "Kahj#@!!45",
    ]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "Password:1jdhQ-9!h$\n"
    wanted_password = ["1jdhQ-9!h$"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'password: "Kahj#@!!45"\n'
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'password:"Kahj#@!!45"\n'
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "Password: '1jdhQ-9!h$'\n"
    wanted_password = ["1jdhQ-9!h$"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "Password:'1jdhQ-9!h$'\n"
    wanted_password = ["1jdhQ-9!h$"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "mot de passe:Kahj#@!!45\n"
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'mot de passe: "Kahj#@!!45"\n'
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'mot de passe:"Kahj#@!!45"\n'
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "mot de passe: 'Kahj#@!!45'\n"
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "mot de passe:'Kahj#@!!45'\n"
    wanted_password = ["Kahj#@!!45"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "password: AB5675.\n"
    wanted_password = ["AB5675"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "password: the password\n"
    wanted_password = ["the password"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'password: "the password"\n'
    wanted_password = ["the password"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = "mot de passe: mon secret\n"
    wanted_password = ["mon secret"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)

    text = 'mot de passe: "mon secret"\n'
    wanted_password = ["mon secret"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)
