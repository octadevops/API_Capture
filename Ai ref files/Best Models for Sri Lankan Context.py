# Recommended Models for CSE (In Order of Preference)

CSE_RECOMMENDED_MODELS = {
    # 1. FinBERT - Best for English financial news
    'primary_sentiment': 'ProsusAI/finbert',
    
    # 2. Financial PhraseBank - Good for specific phrases
    'phrase_sentiment': 'ahmedrachid/FinancialBERT-Sentiment-Analysis',
    
    # 3. StockBERT - For stock movement prediction
    'stock_prediction': 'peterkros/stockbert',
    
    # 4. Multilingual - For Sinhala/Tamil news
    'sinhala_tamil': 'xlm-roberta-base',
    
    # 5. ESG Analysis - For company sustainability
    'esg_analysis': 'yiyanghkust/finbert-esg',
    
    # 6. Forward-looking - For future statements
    'forward_looking': 'yiyanghkust/finbert-fls',
}