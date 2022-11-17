const config = require('./config');
const fs = require('fs');
const { spawn } = require('child_process');
const NodeCache = require('node-cache');
const path = require('path');
const os = require('os');
const logger = require('./log');
const { incrementCacheHit, incrementCacheMiss } = require('./metrics');
const crypto = require('crypto');

const inflight = new Map();
// Duplicating the outputDir into two maps because the gitCaches map should be empty until the clone completes,
// but any requests that come during the clone need access to the output directory, so we put that into another cache
const outputDirs = new Map();
const gitCaches = new NodeCache({
  stdTTL: parseInt(config.cacheExpiry) || 300, // 5 minutes
  checkperiod: parseInt(config.cacheCheckPeriod) || 60, // 1 min
  useClones: false,
});

gitCaches.on('expired', (key, value) => {
  const path = value.path;
  const socket = value.socket;
  const metrics = value.metrics;
  logger.debug(
    { cacheKey: key, path },
    'cached clone of git repo has expired - removing',
  );
  fs.rm(path, { recursive: true, force: true }, (err) => {
    // Under load this key can be overridden by a new clone before this callback is fired
    if (outputDirs.get(key) === path) {
      outputDirs.delete(key);
    }
    if (err) {
      logger.error(
        { cacheKey: key, path, err },
        'unable to delete cached GitHub checkout',
      );
    } else {
      logger.debug(
        { cacheKey: key, path },
        'successfully deleted cache',
      );
    }
  });

  socket.send('cache-summary', {cache: logger.sanitise(key), metrics});
});

class GitHubCache {
  #logContext;
  #socket;
  #path;
  #filePathMatcher;
  #treeRefMatcher;
  #protocol;
  #origin;

  #org;
  #repo;
  #filePath;
  #ref;
  #repoUrl;
  #cacheKey;

  constructor(logContext, requestPath, authorization, socket) {
    const filePathExtractor =
      /(?<protocol>https?).*\/(?:repos\/)?(?<org>[^/]+)\/(?<repo>[^/]+)\/contents\/(?<path>[^?]*)(?:\?ref=(?<ref>.+))?/g;
    const treeRefExtractor =
      /(?<protocol>https?).*\/repos\/(?<org>[^/]+)\/(?<repo>[^/]+)\/git\/trees\/(?<ref>[^?]+)/gi;
    this.#logContext = logContext;
    this.#socket = socket;
    this.#path = requestPath;
    this.#filePathMatcher = filePathExtractor.exec(requestPath);
    this.#treeRefMatcher = treeRefExtractor.exec(requestPath);

    if (this.#filePathMatcher?.groups) {
      this.#origin = config.github;
      this.#protocol = this.#filePathMatcher.groups.protocol;
      this.#org = this.#filePathMatcher.groups.org;
      this.#repo = this.#filePathMatcher.groups.repo;
      this.#filePath = this.#filePathMatcher.groups.path.replaceAll(
        /%2f/gi,
        '/',
      );
      this.#ref = this.#filePathMatcher.groups.ref || 'master';

      this.#repoUrl = `${this.#protocol}://${authorization}@${this.#origin}/${
        this.#org
      }/${this.#repo}.git`;
      this.#cacheKey = `${this.#repoUrl}#${this.#ref}`;

      this.#logContext = {
        ...logContext,
        protocol: this.#protocol,
        origin: this.#origin,
        org: this.#org,
        repo: this.#repo,
        filePath: this.#filePath,
        repoUrl: this.#repoUrl,
        ref: this.#ref,
        cacheKey: this.#cacheKey,
      };
    } else if (this.#treeRefMatcher?.groups) {
      this.#origin = config.github;
      this.#protocol = this.#treeRefMatcher.groups.protocol;
      this.#org = this.#treeRefMatcher.groups.org;
      this.#repo = this.#treeRefMatcher.groups.repo;
      this.#ref = this.#treeRefMatcher.groups.ref || 'master';

      this.#repoUrl = `${this.#protocol}://${authorization}@${this.#origin}/${
        this.#org
      }/${this.#repo}.git`;
      this.#cacheKey = `${this.#repoUrl}#${this.#ref}`;

      this.#logContext = {
        ...logContext,
        protocol: this.#protocol,
        origin: this.#origin,
        org: this.#org,
        repo: this.#repo,
        repoUrl: this.#repoUrl,
        ref: this.#ref,
        cacheKey: this.#cacheKey,
      };
    }
  }

  static enabled() {
    return config.useGitHubCloneCache === 'true';
  }

  pathSupported() {
    return this.#filePathMatcher?.groups;
  }

  pathTriggersCaching() {
    return this.#treeRefMatcher?.groups;
  }

  loadCache() {
    if (gitCaches.has(this.#cacheKey)) {
      logger.trace(
        this.#logContext,
        'git clone cache already exists - ignoring',
      );
      return;
    }

    if (inflight.has(this.#cacheKey)) {
      logger.debug(
        this.#logContext,
        'existing in-flight git clone found - ignoring',
      );
      return;
    }

    const baseDir = config.gitHubCloneDirectory || os.tmpdir();
    const outputDir = fs.mkdtempSync(path.join(baseDir, 'broker-snyk-client'));
    outputDirs.set(this.#cacheKey, outputDir);
    const task = spawn('/bin/sh', [
      '-c',
      `GIT_SSL_NO_VERIFY=true git clone ${
        this.#repoUrl
      } ${outputDir} && cd ${outputDir} && git checkout ${this.#ref}`,
    ]);
    inflight.set(this.#cacheKey, task);

    let stdout = '';
    let stderr = '';
    task.stdout.on('data', (data) => (stdout += data.toString()));
    task.stderr.on('data', (data) => (stderr += data.toString()));
    task.setMaxListeners(0);

    task.on('exit', (code) => {
      inflight.delete(this.#cacheKey);

      if (code) {
        logger.error(
          { ...this.#logContext, code, stdout, stderr },
          'received error performing git clone',
        );
        return;
      }

      gitCaches.set(this.#cacheKey, {path: outputDir, socket: this.#socket, metrics: {hit: 0, miss: 0}});
    });
  }

  handle(hitCallback, missCallback, errorCallback) {
    if (gitCaches.has(this.#cacheKey)) {
      logger.trace(
        this.#logContext,
        'git clone cache found, looking up request',
      );
      this.#checkFsCache(
        gitCaches.get(this.#cacheKey).path,
        hitCallback,
        missCallback,
        errorCallback,
      );
      return true;
    }

    if (inflight.has(this.#cacheKey)) {
      logger.debug(
        this.#logContext,
        'existing in-flight git clone found, adding listener',
      );
      inflight.get(this.#cacheKey).on('exit', (code) => {
        if (code) {
          logger.debug(
            { ...this.#logContext, code },
            'non-zero error code for additional listener - returning error',
          );
          errorCallback(code);
        } else {
          logger.debug(this.#logContext, 'clone succeeded');
          this.#checkFsCache(
            outputDirs.get(this.#cacheKey),
            hitCallback,
            missCallback,
            errorCallback,
          );
        }
      });
      return true;
    }
    this.logMiss();
    return false;
  }

  #checkFsCache(outputDir, hitCallback, missCallback, errorCallback) {
    if (!outputDir || !this.#filePath) {
      this.logMiss();
      logger.error(
        { ...this.#logContext, outputDir },
        'one of outputDir and filePath is undefined',
      );
      if (errorCallback) {
        errorCallback({
          message:
            'unexpected internal error - one or more variables undefined when they should be defined',
        });
      } else {
        logger.error(
          this.#logContext,
          'all arguments passed to function appear undefined - something has gone very wrong',
        );
        console.trace();
      }
      return;
    }
    const pathOnDisk = path.join(outputDir, this.#filePath);
    if (fs.existsSync(pathOnDisk)) {
      this.logHit();
      logger.trace(this.#logContext, 'filePath found in cache');
      fs.readFile(pathOnDisk, (err, data) => {
        if (err) {
          errorCallback(err);
        } else {
          const shasum = crypto.createHash('sha1');
          shasum.update(`blob ${data.length}\0`);
          shasum.update(data);
          const response = {
            name: path.basename(pathOnDisk),
            path: this.#filePath,
            sha: shasum.digest('hex'),
            size: data.length,
            url: null,
            html_url: null,
            git_url: null,
            type: 'file',
            content: data.toString('base64'),
            encoding: 'base64',
            _links: [],
          };

          hitCallback({
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Content-Length': JSON.stringify(response).length,
            },
            body: response,
          });
        }
      });
    } else {
      this.logMiss();
      logger.trace(this.#logContext, 'filePath not found in cache');
      missCallback();
    }
  }

  logHit() {
    incrementCacheHit();
    if (gitCaches.has(this.#cacheKey)) {
      gitCaches.get(this.#cacheKey).metrics.hit += 1;
    }
  }

  logMiss() {
    incrementCacheMiss();
    if (gitCaches.has(this.#cacheKey)) {
      gitCaches.get(this.#cacheKey).metrics.miss += 1;
    }
  }
}

module.exports = {
  GitHubCache,
};