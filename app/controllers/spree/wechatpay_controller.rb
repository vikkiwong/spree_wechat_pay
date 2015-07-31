module Spree
  class WechatpayController < StoreController
    #ssl_allowed
    skip_before_filter :verify_authenticity_token

    GATEWAY_URL = 'https://api.mch.weixin.qq.com/pay'


    # 生成预支付ID，并返回支付options
    def invoke_unifiedorder(order)
      payment_method = Spree::PaymentMethod.find(params[:payment_method_id])
      host = payment_method.preferences[:returnHost].blank? ? request.url.sub(request.fullpath, '') : payment_method.preferences[:returnHost]

      unifiedorder = {
          bank_type: "WX",
          body: "#{order.line_items[0].product.name.slice(0,30)}等#{order.line_items.count}件",
          trade_type: "JSAPI",
          out_trade_no: order.number,
          spbill_create_ip: request.remote_ip || '127.0.0.1',
          total_fee: (order.total*100).to_i,
          fee_type: 1,
          notify_url: host + '/wechatpay/notify?id=' + order.id.to_s + '%26payment_method_id=' + params[:payment_method_id].to_s,
          input_charset: "UTF-8",
          openid: @openid,
          appid: payment_method.preferences[:appId],
          mch_id: payment_method.preferences[:partnerId],
          nonce_str: SecureRandom.hex,
        }.reject{ |k, v| v.blank? }

      Rails.logger.debug('------'*20)

      sign = generate_sign(unifiedorder, payment_method.preferences[:partnerKey])

      res = invoke_remote("#{GATEWAY_URL}/unifiedorder", make_payload(unifiedorder, sign))

      if res && res['return_code'] == 'SUCCESS'

        prepay_id = res['prepay_id']
        Rails.logger.debug("set prepay_id: #{prepay_id}")
        options = {
            appId: payment_method.preferences[:appId],
            timeStamp: Time.now.to_i.to_s,
            nonceStr: SecureRandom.hex,
            package: "prepay_id=#{prepay_id}",
            signType: "MD5",
            #orderNumber: order.number,
        }

        options.merge!( paySign: generate_sign(options, payment_method.preferences[:partnerKey]) )
      else
        Rails.logger.debug '---res---'
        Rails.logger.debug("set prepay_id fail: #{res}")

        {}
      end
    end

    def checkout
      order = if params[:id].present?
              Spree::Order.find(params[:id])
            else
              current_order
            end

      order ||= raise(ActiveRecord::RecordNotFound)

      @openid = if params[:openid].present?  # 有openid 参数
                  params[:openid]

                elsif order.try(:user_id).present?  # 或者订单用户有授权记录
                  wechat_auth = Spree::UserAuthentication.where(user_id: order.user_id, provider: 'wechat').last
                  wechat_auth.try(:uid)
                end
                
      render json: { errCode: 1001, msg: "用户未授权" } and return unless @openid.present?

      render json: invoke_unifiedorder(order)
    end

    def notify
      res = params[:xml]

      order_id, payment_params = res[:id].split("&") if res[:id].present?
      payment_method_id = payment_params.split('=')[1] if payment_params.present?

      order = Spree::Order.find(order_id) || raise(ActiveRecord::RecordNotFound)
      payment_method = Spree::PaymentMethod.find(payment_method_id) || raise(ActiveRecord::RecordNotFound)

      # 验证结果
      unless res[:result_code] == "SUCCESS" && res[:total_fee].to_s == ((order.total*100).to_i).to_s && res[:openid].present?
        render json: "failure", layout: false
        return
      end

      if order.complete?
        render json: "success", layout: false
        return
      end

      order.payments.create!({
        :source => Spree::WechatPayNotify.create({
          :transaction_id => res[:transaction_id],
          :out_trade_no => res[:out_trade_no],
          :open_id => res[:openid],
          :total_fee => res[:total_fee],
          :source_data => res.to_json
        }),
        :amount => order.total,
        :payment_method => payment_method
      })

      order.next

      if order.complete?
        render json: "success", layout: false
      else
        render json: "failure", layout: false
      end
    end

    def query
      order = Spree::Order.find(params[:id]) || raise(ActiveRecord::RecordNotFound)
      payment_method = Spree::PaymentMethod.find(params[:payment_method_id])

      if order.complete?
        render json: { 'errCode' => 0, 'msg' => 'success'} and return
      end

      options = {
        appid: payment_method.preferences[:appId],
        mch_id: payment_method.preferences[:partnerId],
        out_trade_no: order.number,
        nonce_str: SecureRandom.hex,
      }

      sign = generate_sign(options, payment_method.preferences[:partnerKey])

      res = invoke_remote("#{GATEWAY_URL}/unifiedorder", make_payload(options, sign))

      if res && res['return_code'] == 'SUCCESS' && res['result_code'] == 'SUCCESS' && res['trade_state'] == 'SUCCESS'

        order.payments.create!({
          :source => Spree::WechatPayNotify.create({
            :transaction_id => res[:transaction_id],
            :out_trade_no => res[:out_trade_no],
            :open_id => res[:openid],
            :total_fee => res[:total_fee],
            :source_data => res.to_json
          }),
          :amount => order.total,
          :payment_method => payment_method
        })
        order.next
        render json: { 'errCode' => 0, 'msg' => 'success'}
      else
        render json: { 'errCode' => 1, 'msg' => 'failure'}
      end
    end



    private

    def make_payload(params, sign)
      "<xml>#{params.map { |k, v| "<#{k}>#{v}</#{k}>" }.join}<sign>#{sign}</sign></xml>"
    end

    def html_escape(str)
      str.gsub(/&/, '&amp;').gsub(/"/, '&quot;').gsub(/'/, '&#39;').gsub(/</, '&lt;').gsub(/>/, '&gt;')
    end

    def generate_sign(params, appKey)
      query = params.sort.map do |key, value|
        "#{key}=#{html_escape value.to_s}"
      end.join('&')

      Rails.logger.debug '--query&key--'
      Rails.logger.debug "#{query}&key=#{appKey}"

      Rails.logger.debug '--sign--'
      Rails.logger.debug Digest::MD5.hexdigest("#{query}&key=#{appKey}").upcase

      Digest::MD5.hexdigest("#{query}&key=#{appKey}").upcase    
    end

    def invoke_remote(url, payload)
      r = RestClient::Request.execute(
        {
          method: :post,
          url: url,
          payload: payload,
          headers: { content_type: 'application/xml' }
        }.merge({timeout: 2, open_timeout: 3})
      )

      h = Hash.from_xml(r)

      Rails.logger.debug '---h[xml]---'
      Rails.logger.debug h['xml']

      h['xml']
    end
  end
end