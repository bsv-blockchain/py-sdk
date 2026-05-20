from bsv.keys import PrivateKey

# Test code
message = "hello world"

print("Message: ", message)
private_key = PrivateKey("Kzpr5a6TmrXNw2NxSzt6GUonvcP8ABtfU17bdGEjxCufyxGMo9xV")
result = private_key.sign_text(message)
print("\nPython result:")
print(result)
