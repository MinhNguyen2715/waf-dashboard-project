import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
ID2LABEL = {
    0: 'Normal',
    1: 'Path Traversal',
    2: 'Input Data Manipulation',
    3: 'Fake the Source of Data',
    4: 'Code Injection',
    5: 'Scanning for Vulnerable Software',
    6: 'HTTP Response Splitting'
}
class SecBERTModel: 
    def __init__(self, model_path: str = MODEL_DIR):
        self.model_path = model_path 
        print(f"[SecBERT] INFO: Loading model weights from: {self.model_path}")

        try: 
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path) 
        except Exception: 
            print("[SecBERT] WARNING: Local tokenizer files incomplete. Loading fallback 'jackaduma/SecBERT'...") 
            self.tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecBERT")

        # 2. Dựng lại Mô hình SecBERT từ config.json và model.safetensors
        # Build SecBERT from config.json + model.safetensors
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()  # Evaluation mode

        print(f"[SecBERT] SUCCESS: Model successfully rebuilt and active on {self.device}!")

    def predict(self, formatted_payload_text: str) -> str:
        if not formatted_payload_text or not formatted_payload_text.strip():
            return ID2LABEL[0]

        clean_input = formatted_payload_text.strip()

        inputs = self.tokenizer(
            clean_input,
            return_tensors="pt",
            padding='max_length',
            truncation=True,
            max_length=256
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            pred_id = torch.argmax(logits, dim=1).item()

        return ID2LABEL.get(pred_id, 'Normal')

secbert_engine = SecBERTModel()


if __name__ == "__main__":
    print("\n=== RUNNING SECBERT PREDICTION TEST ===")
    
    test_input = (
        "PATH: /index.php?id=1' UNION SELECT 1,2,3-- "
        "| COOKIE: PHPSESSID=abc123xyz "
        "| METHOD: GET "
        "| UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "| BODY:  "
        "| CTYPE: "
    )

    prediction = secbert_engine.predict(test_input)
    
    print(f"Payload Input : {test_input}")
    print(f"AI Prediction : {prediction}")
