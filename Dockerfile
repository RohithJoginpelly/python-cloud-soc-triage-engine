FROM python:3.13-slim

WORKDIR /app

ENV PYTHONPATH=/app/src

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["sh", "-c", "python src/main.py && PYTHONPATH=src python src/report_generator.py && streamlit run dashboard/app.py --server.address=0.0.0.0 --server.port=8501"]
