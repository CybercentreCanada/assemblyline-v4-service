import pytest
from assemblyline_v4_service.common.utils import extract_passwords


def test_extract_passwords():
    # Make sure an empty string doesn't cause any problem
    text = ""
    res = extract_passwords(text)
    assert res == set()

    # Make sure an empty string doesn't cause any problem
    text = "\n"
    res = extract_passwords(text)
    assert res == set()

    # Make sure a string that only contains the text "password:" does not
    # give us an empty password
    text = "Password:"
    res = extract_passwords(text)
    assert res == {"Password", "Password:"}

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

    text = "내 비밀번호는 shibboleet입니다"
    wanted_password = ["shibboleet"]
    res = extract_passwords(text)
    assert all(password in res for password in wanted_password)


@pytest.mark.parametrize(
    "text, password",
    [
        ("Please use attached#password:1234#@!# and tell me if I can do anything else", "1234#@!"),
        ("Please use attached#password:1234#@!## and tell me if I can do anything else", "1234#@!#"),
        ("Please use attached[password:1234#@!] and tell me if I can do anything else", "1234#@!"),
        ("Please use attached<password:1234#@!> and tell me if I can do anything else", "1234#@!"),
        ("Please use attached password:1234#@!) and tell me if I can do anything else", "1234#@!)"),
        ("Please use attached(password:1234#@!) and tell me if I can do anything else", "1234#@!"),
        ("Please use attached(password: 1234#@!) and tell me if I can do anything else", "1234#@!"),
        ("(mot de passe:1234#@!)", "1234#@!"),
        ("(mot de passe: 1234#@!)", "1234#@!"),
        ("(mot de passe: 1234#@!)", " 1234#@!"),
        # Password-keyword starting line shouldn't cause any problem
        ("password:1234# and tell me if I can do anything else", "1234#"),
    ]
)
def test_non_space_password_delimiter(text, password):
    # The use-non-space-as-delimiter
    # if the character preceding the word password in any language is found in the extracted password
    # for that line, split on each.
    # Also check for matching <> () [] {} instead if it's an opening one preceding.
    res = extract_passwords(text)
    assert password in res
