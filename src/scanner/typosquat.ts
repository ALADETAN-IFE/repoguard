/**
 * Known typosquatted package names mapped to the legitimate package they mimic.
 * Sources: PyPI malware reports, npm security advisories, OSSF data.
 * Expand this list as new campaigns are discovered.
 */

export const KNOWN_NPM_TYPOSQUATS: Record<string, string> = {
  // react
  "react-dom-dom": "react-dom",
  reakt: "react",
  rect: "react",
  // lodash
  "lodash-utils": "lodash",
  lodahs: "lodash",
  // express
  expres: "express",
  expresss: "express",
  // axios
  axois: "axios",
  axiox: "axios",
  axio: "axios",
  // moment
  momnet: "moment",
  momen: "moment",
  // webpack
  webpak: "webpack",
  "web-pack": "webpack",
  // typescript
  typscript: "typescript",
  typescrip: "typescript",
  // eslint
  eslin: "eslint",
  "es-lint": "eslint",
  // prettier
  pretter: "prettier",
  pretier: "prettier",
  // next
  "next-js": "next",
  nextjs: "next",
  // colors (notorious malware campaign)
  color: "colors",
  colour: "colors",
  // node-fetch
  "node-fetc": "node-fetch",
  nodefetch: "node-fetch",
  // cross-env
  crossenv: "cross-env",
  "cross-env-cli": "cross-env",
  // dotenv
  "dot-env": "dotenv",
  "dotenv-safe": "dotenv",
  // jsonwebtoken
  "jsonwebtoken-cli": "jsonwebtoken",
  "jwt-simple-token": "jsonwebtoken",
  // bcrypt
  "bcrypt-js": "bcryptjs",
  bcrpyt: "bcrypt",
  // mongoose
  mongosse: "mongoose",
  mongoos: "mongoose",
  // sequelize
  sequlize: "sequelize",
  "sequelize-orm": "sequelize",
  // known malicious packages (real campaigns)
  "ua-parser-js-patched": "ua-parser-js",
  "event-stream-latest": "event-stream",
  "flatmap-stream": "event-stream",
  "bootstrap-sass-official": "bootstrap-sass",
  colourama: "colorama",
  collour: "colour",
};

export const KNOWN_PYPI_TYPOSQUATS: Record<string, string> = {
  // requests
  reqeusts: "requests",
  requets: "requests",
  request: "requests",
  reqests: "requests",
  requests2: "requests",
  // numpy
  nunpy: "numpy",
  numpyy: "numpy",
  nump: "numpy",
  // pandas
  panda: "pandas",
  pandass: "pandas",
  pndas: "pandas",
  // flask
  falsk: "flask",
  flaask: "flask",
  flask2: "flask",
  // django
  djnago: "django",
  djanog: "django",
  djangoo: "django",
  // tensorflow
  tensorfow: "tensorflow",
  tensorflw: "tensorflow",
  tensorfloww: "tensorflow",
  // scikit-learn
  "scikit-learns": "scikit-learn",
  sklearn2: "scikit-learn",
  // pillow
  pilow: "pillow",
  pilows: "pillow",
  pil: "pillow",
  // boto3
  bto3: "boto3",
  bot3: "boto3",
  // sqlalchemy
  sqlalchmy: "sqlalchemy",
  "sql-alchemy": "sqlalchemy",
  // pytest
  "py-test": "pytest",
  pytset: "pytest",
  // setuptools
  "setup-tools": "setuptools",
  setuptool: "setuptools",
  // pip
  pip2: "pip",
  piip: "pip",
  // urllib3
  urlli3: "urllib3",
  "urllib-3": "urllib3",
  // cryptography
  cryptograpy: "cryptography",
  cryptographyy: "cryptography",
  // known real malicious PyPI packages
  colourama: "colorama",
  collour: "colour",
  "python-sqlite": "sqlite3",
  "python3-dateutil": "python-dateutil",
  "py-util": "pyutil",
  dateutil: "python-dateutil",
  "python-mongo": "pymongo",
  "mongo-python": "pymongo",
  diango: "django",
  djanga: "django",
};
