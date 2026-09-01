# Primary Models for CSE Analysis
MODELS = {
    # Financial Sentiment Analysis
    'finbert': 'ProsusAI/finbert',  # Best for English financial news
    'finbert_tone': 'yiyanghkust/finbert-tone',  # Granular sentiment
    'finbert_fls': 'yiyanghkust/finbert-fls',  # Forward-looking statements
    'financial_phrasebank': 'ahmedrachid/FinancialBERT-Sentiment-Analysis',  # Phrase-level sentiment
    
    # Stock Prediction
    'stockbert': 'peterkros/stockbert',  # Stock movement prediction
    'stock_news': 'mrm8488/stock-news-distilbert-roberta',  # Stock news classification
    
    # Market Analysis
    'market_sentiment': 'nickmuchi/finbert-classification',  # Buy/sell/hold signals
    'sec_bert': 'nlpaueb/sec-bert-base',  # Financial document analysis
    'sec_bert_num': 'nlpaueb/sec-bert-num',  # With numerical data
    'sec_bert_shapes': 'nlpaueb/sec-bert-shapes',  # With layout info
    
    # Multilingual Models (for Sinhala/Tamil)
    'xlm_roberta': 'xlm-roberta-base',  # Multilingual support
    'xlm_roberta_large': 'xlm-roberta-large',  # Better performance
    'multilingual_bert': 'bert-base-multilingual-uncased',  # Multilingual BERT
    'indic_bert': 'ai4bharat/indic-bert',  # Indian languages (similar structure)
    
    # General Sentiment (Backup)
    'roberta_sentiment': 'cardiffnlp/twitter-roberta-base-sentiment-latest',  # Twitter sentiment
    'distilbert_sentiment': 'distilbert-base-uncased-finetuned-sst-2-english',  # General sentiment
    'bert_sentiment': 'nlptown/bert-base-multilingual-uncased-sentiment',  # 1-5 star sentiment
    
    # Emerging Market Models
    'emerging_markets': 'gtfintechlab/FinBERT',  # Financial domain BERT
    'finbert_esg': 'yiyanghkust/finbert-esg',  # ESG analysis for companies
    'finbert_pretrain': 'yiyanghkust/finbert-pretrain',  # Pre-trained FinBERT
}

# Specialized Models for Time Series
TIME_SERIES_MODELS = {
    'time_series_transformer': 'ibm/time-series-transformer',  # General forecasting
    'informer': 'huggingface/informer-tourism-monthly',  # Long sequence forecasting
    'autoformer': 'huggingface/autoformer-tourism-monthly',  # Auto-correlation
    'patch_tst': 'namctin/patchtst_etth1_forecast',  # Patch time series
    'time_series_bert': 'vishnun/time-series-transformer',  # Time series BERT
}