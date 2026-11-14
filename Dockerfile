# AgentArts 运行时托管镜像
# 注意：必须在 ARM64 环境（如华为云鲲鹏 ECS Ubuntu 22.04）上构建，
# X86 镜像部署后调用会失败。
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -i https://pypi.org/simple scikit-learn==1.9.1

COPY pyproject.toml ./
COPY src ./src
COPY app.py .
COPY predict.py .
COPY model ./model

ENV PYTHONPATH=/app/src

EXPOSE 8080

ENTRYPOINT ["python", "app.py"]
