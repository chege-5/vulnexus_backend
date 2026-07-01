from transformers import AutoModelForSequenceClassification, AutoTokenizer

model_name = "CIRCL/vulnerability-severity-classification-roberta-base"

tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# save locally
model.save_pretrained("ml_models/vulnerability_model")
tokenizer.save_pretrained("ml_models/vulnerability_model")

print("Model downloaded successfully")