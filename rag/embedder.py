from sentence_transformers import SentenceTransformer   
class ARGUSEmbedder:
    def __init__(self):
        print("ARGUS EMBEDDER : Loading model...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        print("ARGUS Embedder : Ready!")

    def embed(self, text):
        return self.model.encode(text).tolist()


    def embed_many(self,texts):
        return self.model.encode(texts).tolist()
if __name__ == "__main__":
    embedder = ARGUSEmbedder()
    test_text = "Brute Force login attack"
    vector = embedder.embed(test_text)
    print(f"\n Text: '{test_text}'")
    print(f" \n Vector Length: {len(vector)} numbers")
    print(f" First 5 numbers :{vector[:5]}")
    print("\n ARGUS Embedder test working..")