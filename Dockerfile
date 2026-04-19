FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir httpx uvicorn
# OwlSec needs to be available
ENV OWLGUARD_CHARWIZ_SRC=/app/charwiz/src
EXPOSE 8800
CMD ["python", "-m", "src.app"]
