const http = require('http');
const assert = require('assert');

console.log('开始角色管理API测试');

// 服务配置
const API_HOST = process.env.API_HOST || 'localhost';
const API_PORT = process.env.API_PORT || 8081;

// 生成随机名称
function generateRandomName() {
  return '测试角色_' + Math.random().toString(36).substring(2, 8);
}

// HTTP请求函数
function request(options, data = null) {
  // 使用环境变量中的主机和端口
  options.hostname = API_HOST;
  options.port = API_PORT;

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

// 运行角色管理测试
async function runCharacterTest() {
  try {
    // 先登录获取token
    console.log('\n登录测试用户...');
    const loginData = {
      username: 'testuser',
      password: 'testpass'
    };

    let accessToken;
    try {
      const loginRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: '/api/auth/login',
        method: 'POST'
      }, loginData);

      assert.strictEqual(loginRes.statusCode, 200, '登录请求应返回200状态码');
      accessToken = loginRes.parsedBody.access_token;
      console.log('  用户登录成功');
    } catch (error) {
      console.log('  登录失败:', error.message);
      return;
    }

    // 测试创建角色
    console.log('\n测试创建角色API...');
    const characterName = generateRandomName();
    const createCharacterData = {
      name: characterName,
      description: '这是一个测试角色',
      age: 25,
      gender: '男',
      background: '角色背景故事...',
      personality: ['性格特点1', '性格特点2'],
      goals: ['目标1', '目标2']
    };

    let characterId;
    try {
      const createRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: '/api/characters',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }, createCharacterData);

      assert.strictEqual(createRes.statusCode, 200, '创建角色请求应返回200状态码');
      assert.ok(createRes.parsedBody.id, '响应应包含角色ID');
      assert.strictEqual(createRes.parsedBody.name, characterName, '角色名称不匹配');
      characterId = createRes.parsedBody.id;
      console.log('  创建角色测试通过');

      // 测试获取角色详情
      console.log('\n测试获取角色详情API...');
      const getCharacterRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      assert.strictEqual(getCharacterRes.statusCode, 200, '获取角色详情请求应返回200状态码');
      assert.strictEqual(getCharacterRes.parsedBody.name, characterName, '获取的角色名称不匹配');
      console.log('  获取角色详情测试通过');

      // 测试更新角色信息
      console.log('\n测试更新角色信息API...');
      const updateData = {
        name: characterName + '_已更新',
        description: '这是更新后的角色描述'
      };

      const updateRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}`,
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }, updateData);

      assert.strictEqual(updateRes.statusCode, 200, '更新角色信息请求应返回200状态码');
      console.log('  更新角色信息测试通过');

      // 测试添加角色关系
      console.log('\n测试添加角色关系API...');

      // 先创建另一个角色
      const otherCharacterName = generateRandomName() + '_其他';
      const otherCharacterData = {
        name: otherCharacterName,
        description: '这是另一个测试角色',
        age: 30,
        gender: '女'
      };

      const createOtherRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: '/api/characters',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }, otherCharacterData);

      const otherCharacterId = createOtherRes.parsedBody.id;

      // 创建角色关系
      const createRelationData = {
        target_character_id: otherCharacterId,
        relationship_type: '朋友',
        description: '两人是多年好友'
      };

      const createRelationRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}/relationships`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }, createRelationData);

      assert.strictEqual(createRelationRes.statusCode, 200, '添加角色关系请求应返回200状态码');
      console.log('  添加角色关系测试通过');

      // 测试获取角色关系列表
      console.log('\n测试获取角色关系列表API...');
      const getRelationsRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}/relationships`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      assert.strictEqual(getRelationsRes.statusCode, 200, '获取角色关系列表请求应返回200状态码');
      assert.ok(Array.isArray(getRelationsRes.parsedBody), '角色关系列表应该是数组');
      assert.ok(getRelationsRes.parsedBody.length > 0, '角色关系列表不应为空');
      console.log('  获取角色关系列表测试通过');

      // 测试添加角色对话
      console.log('\n测试添加角色对话API...');
      const createDialogueData = {
        content: '这是一段测试对话内容',
        context: '在某个场景中',
        tone: '正式'
      };

      const createDialogueRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}/dialogues`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      }, createDialogueData);

      assert.strictEqual(createDialogueRes.statusCode, 200, '添加角色对话请求应返回200状态码');
      const dialogueId = createDialogueRes.parsedBody.id;
      console.log('  添加角色对话测试通过');

      // 测试删除角色
      console.log('\n测试删除角色API...');
      const deleteCharacterRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}`,
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      assert.strictEqual(deleteCharacterRes.statusCode, 200, '删除角色请求应返回200状态码');
      console.log('  删除角色测试通过');

      // 验证角色已被删除
      console.log('\n验证角色已被删除...');
      const checkDeletedRes = await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${characterId}`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      assert.strictEqual(checkDeletedRes.statusCode, 404, '查询已删除的角色应返回404状态码');
      console.log('  验证角色删除测试通过');

      // 清理：删除第二个角色
      await request({
        hostname: 'localhost',
        port: 8081,
        path: `/api/characters/${otherCharacterId}`,
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

    } catch (error) {
      console.error('  测试失败:', error);
      throw error;
    }
  } catch (error) {
    console.error('测试过程中发生错误:', error);
  }
}

// 运行测试
runCharacterTest().then(() => {
  console.log('\n角色管理API测试完成');
}).catch(error => {
  console.error('测试执行失败:', error);
});
