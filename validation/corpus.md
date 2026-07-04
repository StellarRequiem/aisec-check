# aisec-check validation corpus

Real, public, actively-maintained repositories that are aisec-check's **actual target
audience**: MCP servers, LLM agent frameworks, RAG apps, and AI-tool / inference wrappers
— Python-heavy codebases where the vuln classes aisec-check flags (unsafe deserialization,
SSRF-on-model-controlled-URL, template/command injection, hardcoded/plaintext secrets,
auth-bypass/IDOR in tool routes) actually recur.

**Purpose.** This list is the input to `corpus-scan.yml`, which — **in a disposable CI
runner, read-only, never executing the cloned code** — runs `aisec-check scan` over each
repo and uploads the raw findings. Precision is computed **after human adjudication** (the
next phase); this file only fixes the sample. See `README.md` for the isolation model.

**Curation rule.** Every entry is a repo whose existence and owner/name slug I confirmed
via web research (GitHub, awesome-mcp lists, huntr's AI/ML OSV program). A mix of
well-known flagships and smaller projects, deliberately, so precision isn't measured only
on the most-hardened code. Slugs can move (redirects on GitHub resolve); the scan clones by
URL so a moved repo still resolves.

Columns: **owner/name** · **url** · **why in corpus**

---

## MCP servers & SDKs (the tool-call / server-side attack surface)

| owner/name | url | why in corpus |
|---|---|---|
| modelcontextprotocol/servers | https://github.com/modelcontextprotocol/servers | Official reference MCP servers (fetch, git, filesystem, memory, time) — the canonical tool-call surface aisec-check targets |
| modelcontextprotocol/python-sdk | https://github.com/modelcontextprotocol/python-sdk | Official MCP Python SDK; server/tool scaffolding most MCP servers build on |
| jlowin/fastmcp | https://github.com/jlowin/fastmcp | FastMCP — the dominant Pythonic framework for building MCP servers/clients; decorator-defined tool routes |
| github/github-mcp-server | https://github.com/github/github-mcp-server | GitHub's official MCP server; privileged tool actions over a real API |
| spences10/mcp-omnisearch | https://github.com/spences10/mcp-omnisearch | Smaller MCP server fanning out to Tavily/Brave/Exa/Firecrawl — many outbound URL fetches (SSRF surface) |
| zcaceres/fetch-mcp | https://github.com/zcaceres/fetch-mcp | Flexible HTTP-fetching MCP server — server-side fetch of caller-controlled URLs |
| evalstate/mcp-py-repl | https://github.com/evalstate/mcp-py-repl | A Python REPL exposed as an MCP tool — code-execution / injection surface by design |
| chroma-core/chroma-mcp | https://github.com/chroma-core/chroma-mcp | Chroma's MCP server bridging an LLM to a vector DB (RAG retrieval tool surface) |
| ruslanmv/Simple-MCP-Server-with-Python | https://github.com/ruslanmv/Simple-MCP-Server-with-Python | Small tutorial-grade MCP server — representative of the long tail of AI-built servers |

## LLM agent frameworks (tool orchestration, dynamic execution)

| owner/name | url | why in corpus |
|---|---|---|
| langchain-ai/langchain | https://github.com/langchain-ai/langchain | The most-used LLM app framework; agents/chains/tools — historically a source of SSRF & deserialization CVEs |
| langchain-ai/langgraph | https://github.com/langchain-ai/langgraph | Stateful graph agent runtime from LangChain; tool-execution surface |
| run-llama/llama_index | https://github.com/run-llama/llama_index | LlamaIndex — RAG + agent framework; loaders/query engines pull external data |
| crewAIInc/crewAI | https://github.com/crewAIInc/crewAI | CrewAI — role-playing multi-agent orchestrator (~50k+ stars); dynamic tool calls |
| microsoft/autogen | https://github.com/microsoft/autogen | AutoGen — multi-agent conversation framework; code-execution agents |
| deepset-ai/haystack | https://github.com/deepset-ai/haystack | Haystack — production RAG/agent orchestration; pipeline components fetch & template |
| pydantic/pydantic-ai | https://github.com/pydantic/pydantic-ai | Pydantic AI — type-safe agent framework; tool schemas & execution |
| transformeroptimus/SuperAGI | https://github.com/TransformerOptimus/SuperAGI | Autonomous-agent framework with tool plugins; broad third-party integration surface |
| assafelovic/gpt-researcher | https://github.com/assafelovic/gpt-researcher | Autonomous research agent — heavy outbound web fetching (SSRF-shaped) |
| yoheinakajima/babyagi | https://github.com/yoheinakajima/babyagi | BabyAGI — canonical small autonomous-agent loop; representative smaller project |
| OpenBMB/ChatDev | https://github.com/OpenBMB/ChatDev | Multi-agent "software company"; agents generate & run code |
| geekan/MetaGPT | https://github.com/geekan/MetaGPT | Multi-agent framework that writes/executes code and templates |
| Significant-Gravitas/AutoGPT | https://github.com/Significant-Gravitas/AutoGPT | AutoGPT — flagship autonomous agent; large plugin/tool attack surface |

## RAG apps & platforms (retrieval + user content + templating)

| owner/name | url | why in corpus |
|---|---|---|
| langgenius/dify | https://github.com/langgenius/dify | Dify — LLM app platform with visual RAG/workflow builder; huntr OSV target |
| infiniflow/ragflow | https://github.com/infiniflow/ragflow | RAGFlow — deep-document-understanding RAG engine; file ingestion surface |
| explodinggradients/ragas | https://github.com/explodinggradients/ragas | Ragas — RAG evaluation framework; huntr OSV target |
| embedchain/embedchain | https://github.com/embedchain/embedchain | Embedchain/Mem0 RAG bot framework over arbitrary datasets; data loaders |
| mem0ai/mem0 | https://github.com/mem0ai/mem0 | Mem0 — memory layer for LLM apps; store/retrieve + integrations |
| imartinez/privateGPT | https://github.com/zylon-ai/private-gpt | PrivateGPT — local RAG over documents; ingestion & templating |
| Chainlit/chainlit | https://github.com/Chainlit/chainlit | Chainlit — conversational-AI app framework; user-facing routes & auth |
| danny-avila/LibreChat | https://github.com/danny-avila/LibreChat | LibreChat — self-hosted multi-model chat app; auth + agents; huntr OSV target |
| lm-sys/FastChat | https://github.com/lm-sys/FastChat | FastChat — serve/eval LLM chatbots; model-serving API surface; huntr OSV target |
| zilliztech/GPTCache | https://github.com/zilliztech/GPTCache | GPTCache — semantic cache for LLMs; serialization of cached entries; huntr OSV target |
| netease-youdao/QAnything | https://github.com/netease-youdao/QAnything | QAnything — local knowledge-base QA (RAG); document ingestion |
| deepset-ai/haystack-core-integrations | https://github.com/deepset-ai/haystack-core-integrations | Haystack integration components — many third-party connectors, smaller per-module surface |

## AI-tool / inference / gateway wrappers (secrets, outbound calls, deserialization)

| owner/name | url | why in corpus |
|---|---|---|
| BerriAI/litellm | https://github.com/BerriAI/litellm | LiteLLM — gateway/proxy to 100+ LLM APIs; credential handling + outbound provider calls |
| vllm-project/vllm | https://github.com/vllm-project/vllm | vLLM — high-throughput inference server; model loading (torch/pickle) + API surface |
| huggingface/text-generation-inference | https://github.com/huggingface/text-generation-inference | HF TGI — production inference server; model download/load + serving |
| guardrails-ai/guardrails | https://github.com/guardrails-ai/guardrails | Guardrails — validation/guardrail layer; loads validators, parses model output |
| openai/openai-python | https://github.com/openai/openai-python | Official OpenAI Python SDK; API-key handling patterns (secret-shape detectors) |
| anthropics/anthropic-sdk-python | https://github.com/anthropics/anthropic-sdk-python | Official Anthropic Python SDK; credential + client patterns |
| Arize-ai/phoenix | https://github.com/Arize-ai/phoenix | Phoenix — LLM observability; ingests traces/spans, server component |
| langfuse/langfuse | https://github.com/langfuse/langfuse | Langfuse — LLM engineering/observability platform; API keys + ingestion |
| BerriAI/reliableGPT | https://github.com/BerriAI/reliableGPT | Smaller reliability wrapper around LLM calls; outbound call handling |
| jina-ai/clip-as-service | https://github.com/jina-ai/clip-as-service | CLIP-as-service — model serving over the wire; smaller/older but active |

## AI/ML libraries with a documented deserialization / model-file surface (huntr OSV/MFV)

| owner/name | url | why in corpus |
|---|---|---|
| feast-dev/feast | https://github.com/feast-dev/feast | Feast — feature store; serialization of feature values; huntr OSV target |
| Netflix/metaflow | https://github.com/Netflix/metaflow | Metaflow — ML workflow framework; artifact (pickle) serialization; huntr OSV target |
| aws/sagemaker-python-sdk | https://github.com/aws/sagemaker-python-sdk | SageMaker Python SDK — model packaging/loading; huntr OSV target |
| mlflow/mlflow | https://github.com/mlflow/mlflow | MLflow — model registry/serving; pickle/model loading; recurrent deserialization CVEs |
| ray-project/ray | https://github.com/ray-project/ray | Ray — distributed compute for ML/serving; cloudpickle across the wire |
| bentoml/BentoML | https://github.com/bentoml/BentoML | BentoML — model serving/packaging; artifact loading + service routes |
| skops-dev/skops | https://github.com/skops-dev/skops | skops — safer sklearn model persistence; directly in the model-file threat model |
| onnx/onnx | https://github.com/onnx/onnx | ONNX — model format lib; protobuf/model parsing; huntr MFV format target |
| triton-inference-server/server | https://github.com/triton-inference-server/server | Triton Inference Server — model repository loading + serving surface |
| kserve/kserve | https://github.com/kserve/kserve | KServe — model inference on Kubernetes; model pull/load + predict routes |

## Vector DB / retrieval clients (RAG data plane)

| owner/name | url | why in corpus |
|---|---|---|
| chroma-core/chroma | https://github.com/chroma-core/chroma | Chroma — embeddings/vector DB; server + client; RAG data plane |
| weaviate/weaviate-python-client | https://github.com/weaviate/weaviate-python-client | Weaviate Python client; connection/credential handling |
| qdrant/qdrant-client | https://github.com/qdrant/qdrant-client | Qdrant Python client; RAG retrieval client surface |
| milvus-io/pymilvus | https://github.com/milvus-io/pymilvus | PyMilvus — Milvus client; unauth-access-shaped patterns in RAG stacks |
| lancedb/lancedb | https://github.com/lancedb/lancedb | LanceDB — embedded vector DB; smaller, fast-moving RAG store |
