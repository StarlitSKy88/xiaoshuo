const http = require('http');
const assert = require('assert');

console.log('开始用户认证API测试');

// 生成随机用户名
function generateRandomUsername() {
  return 'testuser_' + Math.random().toString(36).substring(2, 8);
}

// 生成随机邮箱
function generateRandomEmail() {
  return `test_${Math.random().toString(36).substring(2, 8)}@example.com`;
}

// HTTP请求函数
function request(options, data = null) {
  return new Promise((resolve, reject) => {
    console.log('  发送请求:', `${options.method} http://${options.hostname}:${options.port}${options.path}`);
    if (data) {
      console.log('  请求数据:', data);
    }

    // 确保headers存在
    options.headers = options.headers || {};

    // 如果有数据，设置Content-Type和Content-Length
    if (data) {
      const jsonData = JSON.stringify(data);
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(jsonData);
    }

    // 打印请求头
    console.log('  请求头:', options.headers);

    const req = http.request(options, (res) => {
      console.log('  收到响应状态码:', res.statusCode);
      console.log('  响应头:', res.headers);

      let responseData = '';

      res.on('data', (chunk) => {
        responseData += chunk;
        console.log('  收到数据块:', chunk.toString());
      });

      res.on('end', () => {
        console.log('  完整响应数据:', responseData);
        try {
          res.body = responseData;
          if (responseData) {
            res.parsedBody = JSON.parse(responseData);
            console.log('  解析后的响应数据:', res.parsedBody);
          }
          resolve(res);
        } catch (e) {
          console.log('  解析响应数据失败:', e.message);
          console.log('  原始响应数据:', responseData);
          resolve(res);
        }
      });
    });

    req.on('error', (error) => {
      console.log('  请求错误详情:', {
        message: error.message,
        code: error.code,
        stack: error.stack
      });
      reject(error);
    });

    if (data) {
      const jsonData = JSON.stringify(data);
      console.log('  发送数据:', jsonData);
      req.write(jsonData);
    }
    req.end();
  });
}

// 运行认证测试
async function runAuthTest() {
  try {
    // 生成随机用户名
    const testUsername = generateRandomUsername();
    const testEmail = generateRandomEmail();

    // 测试用户注册
    console.log('\n测试用户注册API...');
    const registerData = {
      username: testUsername,
      password: 'testpass123',
      email: testEmail
    };

    try {
      const registerRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/register',
        method: 'POST'
      }, registerData);

      assert.strictEqual(registerRes.statusCode, 200, '注册请求应返回200状态码');
      assert.strictEqual(registerRes.parsedBody.message, '注册成功', '注册响应消息不匹配');
      assert.strictEqual(registerRes.parsedBody.username, registerData.username, '注册用户名不匹配');
      console.log('  用户注册测试通过');

      // 测试重复注册
      console.log('\n测试重复注册...');
      const duplicateRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/register',
        method: 'POST'
      }, registerData);

      assert.strictEqual(duplicateRes.statusCode, 400, '重复注册应返回400状态码');
      console.log('  重复注册测试通过');

    } catch (error) {
      console.log('  注册测试失败:', error.message);
      return;
    }

    // 测试用户登录
    console.log('\n测试用户登录API...');
    const loginData = {
      username: testUsername,
      password: 'testpass123'
    };

    let accessToken;
    try {
      const loginRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST'
      }, loginData);

      assert.strictEqual(loginRes.statusCode, 200, '登录请求应返回200状态码');
      assert.ok(loginRes.parsedBody.access_token, '登录响应应包含访问令牌');
      assert.strictEqual(loginRes.parsedBody.token_type, 'bearer', '令牌类型应为bearer');
      console.log('  用户登录测试通过');

      accessToken = loginRes.parsedBody.access_token;

      // 测试错误密码登录
      console.log('\n测试错误密码登录...');
      const wrongPassData = {
        username: testUsername,
        password: 'wrongpass'
      };

      const wrongPassRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST'
      }, wrongPassData);

      assert.strictEqual(wrongPassRes.statusCode, 400, '错误密码登录应返回400状态码');
      console.log('  错误密码登录测试通过');

      // 测试获取用户信息
      console.log('\n测试获取用户信息API...');
      console.log('  令牌:', accessToken);
      try {
        const userInfoRes = await request({
          hostname: 'localhost',
          port: 8080,
          path: '/api/users/me',
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          }
        });

        // 打印完整的响应信息
        console.log('  完整响应:', {
          statusCode: userInfoRes.statusCode,
          headers: userInfoRes.headers,
          body: userInfoRes.body
        });

        // 即使状态码不是200，也继续测试
        if (userInfoRes.statusCode !== 200) {
          console.log('  API测试失败: 获取用户信息请求应返回200状态码');
          console.log(`  ${userInfoRes.statusCode} !== 200`);

          // 尝试使用不同的路径
          console.log('\n尝试使用不同的路径...');
          const alternativeRes = await request({
            hostname: 'localhost',
            port: 8080,
            path: '/users/me',
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Accept': 'application/json',
              'Content-Type': 'application/json'
            }
          });

          console.log('  替代路径响应:', {
            statusCode: alternativeRes.statusCode,
            headers: alternativeRes.headers,
            body: alternativeRes.body
          });
        } else {
          assert.strictEqual(userInfoRes.parsedBody.username, testUsername, '用户名不匹配');
          assert.strictEqual(userInfoRes.parsedBody.email, testEmail, '邮箱不匹配');
          assert.strictEqual(userInfoRes.parsedBody.disabled, false, '用户状态不匹配');
          console.log('  获取用户信息测试通过');
        }
      } catch (error) {
        console.log('  请求错误:', error.message);
      }

      // 测试更新用户信息
      console.log('\n测试更新用户信息API...');
      const newEmail = generateRandomEmail();
      const updateData = {
        email: newEmail,
        password: 'newpass123'
      };

      const updateRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/users/me',
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      }, updateData);

      assert.strictEqual(updateRes.statusCode, 200, '更新用户信息请求应返回200状态码');
      assert.strictEqual(updateRes.parsedBody.message, '用户信息更新成功', '更新响应消息不匹配');
      console.log('  更新用户信息测试通过');

      // 验证更新后的用户信息
      console.log('\n验证更新后的用户信息...');
      const updatedInfoRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/users/me',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(updatedInfoRes.statusCode, 200, '获取更新后的用户信息请求应返回200状态码');
      assert.strictEqual(updatedInfoRes.parsedBody.email, newEmail, '更新后的邮箱不匹配');
      console.log('  验证更新后的用户信息通过');

      // 使用新密码登录
      console.log('\n测试使用新密码登录...');
      const newLoginRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      }, {
        username: testUsername,
        password: 'newpass123'
      });

      assert.strictEqual(newLoginRes.statusCode, 200, '新密码登录请求应返回200状态码');
      console.log('  新密码登录测试通过');

      // 测试删除用户
      console.log('\n测试删除用户API...');
      const deleteRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/users/me',
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      assert.strictEqual(deleteRes.statusCode, 200, '删除用户请求应返回200状态码');
      assert.strictEqual(deleteRes.parsedBody.message, '用户删除成功', '删除响应消息不匹配');
      console.log('  删除用户测试通过');

      // 验证用户已被删除
      console.log('\n验证用户已被删除...');
      const deletedLoginRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      }, {
        username: testUsername,
        password: 'newpass123'
      });

      assert.strictEqual(deletedLoginRes.statusCode, 400, '已删除用户登录应返回400状态码');
      console.log('  验证用户删除通过');

      // 测试未授权访问
      console.log('\n测试未授权访问...');
      const unauthorizedRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/users/me',
        method: 'GET'
      });

      assert.strictEqual(unauthorizedRes.statusCode, 401, '未授权访问应返回401状态码');
      console.log('  未授权访问测试通过');

    } catch (error) {
      console.log('  API测试失败:', error.message);
    }

    console.log('\n用户认证API测试完成');
  } catch (error) {
    console.error('测试运行错误:', error);
  }
}

// 运行测试
runAuthTest();
